#!/usr/bin/env python3
"""
Linux System Diagnostics MCP Server

This MCP server provides tools to diagnose Linux system issues,
check configurations, and understand system behavior.
"""

import asyncio
import subprocess
import json
import os
import re
from typing import Any, Sequence
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio


# Initialize the MCP server
server = Server("linux-diagnostics")


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available diagnostic tools"""
    return [
        types.Tool(
            name="check_service_status",
            description="Check the status of a systemd service and related logs",
            inputSchema={
                "type": "object",
                "properties": {
                    "service_name": {
                        "type": "string",
                        "description": "Name of the systemd service to check"
                    },
                    "include_logs": {
                        "type": "boolean",
                        "description": "Include recent journal logs",
                        "default": True
                    }
                },
                "required": ["service_name"]
            }
        ),
        types.Tool(
            name="check_port_usage",
            description="Check what's using a specific port and related network info",
            inputSchema={
                "type": "object",
                "properties": {
                    "port": {
                        "type": "integer",
                        "description": "Port number to check"
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["tcp", "udp", "both"],
                        "description": "Protocol to check",
                        "default": "both"
                    }
                },
                "required": ["port"]
            }
        ),
        types.Tool(
            name="check_disk_space",
            description="Check disk space usage and identify large files/directories",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to check (default: /)",
                        "default": "/"
                    },
                    "find_large_files": {
                        "type": "boolean",
                        "description": "Find largest files in the path",
                        "default": True
                    }
                }
            }
        ),
        types.Tool(
            name="check_process_info",
            description="Get detailed information about running processes",
            inputSchema={
                "type": "object",
                "properties": {
                    "process_name": {
                        "type": "string",
                        "description": "Process name or pattern to search for"
                    },
                    "include_children": {
                        "type": "boolean",
                        "description": "Include child processes",
                        "default": True
                    }
                },
                "required": ["process_name"]
            }
        ),
        types.Tool(
            name="check_config_file",
            description="Validate and analyze configuration files",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to configuration file"
                    },
                    "config_type": {
                        "type": "string",
                        "enum": ["nginx", "apache", "ssh", "generic"],
                        "description": "Type of config file for specialized validation",
                        "default": "generic"
                    }
                },
                "required": ["file_path"]
            }
        ),
        types.Tool(
            name="check_system_resources",
            description="Check overall system resource usage (CPU, memory, I/O)",
            inputSchema={
                "type": "object",
                "properties": {
                    "duration": {
                        "type": "integer",
                        "description": "How long to monitor in seconds",
                        "default": 5
                    }
                }
            }
        ),
        types.Tool(
            name="check_network_connectivity",
            description="Test network connectivity and DNS resolution",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target hostname or IP to test"
                    },
                    "test_type": {
                        "type": "string",
                        "enum": ["ping", "dns", "port", "trace"],
                        "description": "Type of network test",
                        "default": "ping"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port number (for port test)",
                        "default": 80
                    }
                },
                "required": ["target"]
            }
        )
    ]


async def run_command(cmd: str, timeout: int = 30) -> dict:
    """Execute a shell command safely and return results"""
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), 
            timeout=timeout
        )
        
        return {
            "returncode": process.returncode,
            "stdout": stdout.decode('utf-8', errors='ignore'),
            "stderr": stderr.decode('utf-8', errors='ignore')
        }
    except asyncio.TimeoutError:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds"
        }
    except Exception as e:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": f"Error executing command: {str(e)}"
        }


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent]:
    """Handle tool calls"""
    
    if name == "check_service_status":
        service_name = arguments.get("service_name")
        include_logs = arguments.get("include_logs", True)
        
        # Check service status
        status_result = await run_command(f"systemctl status {service_name}")
        
        result = f"=== Service Status for {service_name} ===\n"
        result += status_result["stdout"]
        
        if status_result["stderr"]:
            result += f"\nErrors:\n{status_result['stderr']}"
        
        # Include recent logs if requested
        if include_logs:
            logs_result = await run_command(
                f"journalctl -u {service_name} --no-pager -n 20"
            )
            result += f"\n\n=== Recent Logs ===\n{logs_result['stdout']}"
        
        return [types.TextContent(type="text", text=result)]
    
    elif name == "check_port_usage":
        port = arguments.get("port")
        protocol = arguments.get("protocol", "both")
        
        result = f"=== Port {port} Usage ===\n"
        
        if protocol in ["tcp", "both"]:
            tcp_result = await run_command(f"netstat -tlnp | grep :{port}")
            if tcp_result["stdout"]:
                result += f"TCP connections:\n{tcp_result['stdout']}\n"
            
        if protocol in ["udp", "both"]:
            udp_result = await run_command(f"netstat -ulnp | grep :{port}")
            if udp_result["stdout"]:
                result += f"UDP connections:\n{udp_result['stdout']}\n"
        
        # Also check with ss (modern alternative)
        ss_result = await run_command(f"ss -tulpn | grep :{port}")
        if ss_result["stdout"]:
            result += f"\nDetailed socket info:\n{ss_result['stdout']}"
        
        return [types.TextContent(type="text", text=result)]
    
    elif name == "check_disk_space":
        path = arguments.get("path", "/")
        find_large_files = arguments.get("find_large_files", True)
        
        result = f"=== Disk Space Analysis for {path} ===\n"
        
        # Basic disk usage
        df_result = await run_command(f"df -h {path}")
        result += f"Filesystem usage:\n{df_result['stdout']}\n"
        
        # Directory sizes
        du_result = await run_command(f"du -h -d 1 {path} | sort -hr")
        result += f"\nDirectory sizes:\n{du_result['stdout']}\n"
        
        if find_large_files:
            # Find largest files
            large_files = await run_command(
                f"find {path} -type f -size +100M -exec ls -lh {{}} \\; 2>/dev/null | head -10"
            )
            if large_files["stdout"]:
                result += f"\nLargest files (>100MB):\n{large_files['stdout']}"
        
        return [types.TextContent(type="text", text=result)]
    
    elif name == "check_process_info":
        process_name = arguments.get("process_name")
        include_children = arguments.get("include_children", True)
        
        result = f"=== Process Information for {process_name} ===\n"
        
        # Find processes
        ps_result = await run_command(f"ps aux | grep {process_name} | grep -v grep")
        result += f"Running processes:\n{ps_result['stdout']}\n"
        
        if include_children:
            # Get process tree
            pstree_result = await run_command(f"pstree -p | grep {process_name}")
            if pstree_result["stdout"]:
                result += f"\nProcess tree:\n{pstree_result['stdout']}\n"
        
        # Memory and CPU usage
        top_result = await run_command(f"top -b -n 1 | grep {process_name}")
        if top_result["stdout"]:
            result += f"\nResource usage:\n{top_result['stdout']}"
        
        return [types.TextContent(type="text", text=result)]
    
    elif name == "check_config_file":
        file_path = arguments.get("file_path")
        config_type = arguments.get("config_type", "generic")
        
        result = f"=== Configuration Analysis: {file_path} ===\n"
        
        # Check if file exists and permissions
        stat_result = await run_command(f"ls -la {file_path}")
        result += f"File info:\n{stat_result['stdout']}\n"
        
        # Basic syntax check based on config type
        if config_type == "nginx":
            syntax_result = await run_command("nginx -t")
            result += f"Nginx syntax check:\n{syntax_result['stdout']}\n{syntax_result['stderr']}\n"
        elif config_type == "apache":
            syntax_result = await run_command("apache2ctl configtest")
            result += f"Apache syntax check:\n{syntax_result['stdout']}\n{syntax_result['stderr']}\n"
        
        # Show file contents (first 50 lines)
        content_result = await run_command(f"head -n 50 {file_path}")
        result += f"\nFile contents (first 50 lines):\n{content_result['stdout']}"
        
        return [types.TextContent(type="text", text=result)]
    
    elif name == "check_system_resources":
        duration = arguments.get("duration", 5)
        
        result = "=== System Resource Check ===\n"
        
        # CPU info
        cpu_result = await run_command("top -b -n 1 | head -n 5")
        result += f"CPU usage:\n{cpu_result['stdout']}\n"
        
        # Memory info
        mem_result = await run_command("free -h")
        result += f"Memory usage:\n{mem_result['stdout']}\n"
        
        # Load average
        load_result = await run_command("uptime")
        result += f"Load average:\n{load_result['stdout']}\n"
        
        # I/O stats
        iostat_result = await run_command("iostat -x 1 1")
        result += f"I/O statistics:\n{iostat_result['stdout']}"
        
        return [types.TextContent(type="text", text=result)]
    
    elif name == "check_network_connectivity":
        target = arguments.get("target")
        test_type = arguments.get("test_type", "ping")
        port = arguments.get("port", 80)
        
        result = f"=== Network Connectivity Test: {target} ===\n"
        
        if test_type == "ping":
            ping_result = await run_command(f"ping -c 4 {target}")
            result += f"Ping test:\n{ping_result['stdout']}\n{ping_result['stderr']}"
        
        elif test_type == "dns":
            dns_result = await run_command(f"nslookup {target}")
            result += f"DNS lookup:\n{dns_result['stdout']}"
            
            # Also try dig
            dig_result = await run_command(f"dig {target}")
            result += f"\nDetailed DNS info:\n{dig_result['stdout']}"
        
        elif test_type == "port":
            nc_result = await run_command(f"nc -zv {target} {port}", timeout=10)
            result += f"Port {port} test:\n{nc_result['stdout']}\n{nc_result['stderr']}"
        
        elif test_type == "trace":
            trace_result = await run_command(f"traceroute {target}")
            result += f"Traceroute:\n{trace_result['stdout']}"
        
        return [types.TextContent(type="text", text=result)]
    
    else:
        raise ValueError(f"Unknown tool: {name}")


async def main():
    # Run the server using stdin/stdout streams
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="linux-diagnostics",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
