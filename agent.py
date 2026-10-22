import asyncio
import sys
from contextlib import AsyncExitStack
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


PROJECT_DIR = Path(__file__).resolve().parent
SANDBOX_DIR = PROJECT_DIR / "sandbox"
SANDBOX_DIR.mkdir(exist_ok=True)

SERVER_PARAMS = {
    "text-tools": StdioServerParameters(
        command=sys.executable,
        args=[str(PROJECT_DIR / "mcp-server.py")],
    ),
    "filesystem": StdioServerParameters(
        command="npx",
        args=[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            str(SANDBOX_DIR),
        ],
    ),
}


async def main() -> None:
    """Connect to both MCP servers and list the tools they provide."""
    async with AsyncExitStack() as stack:
        for server_name, server_params in SERVER_PARAMS.items():
            read_stream, write_stream = await stack.enter_async_context(
                stdio_client(server_params)
            )
            session = await stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            await session.initialize()
            tools = await session.list_tools()

            print(f"{server_name} tools:")
            for tool in tools.tools:
                print(f"- {tool.name}")


if __name__ == "__main__":
    asyncio.run(main())
