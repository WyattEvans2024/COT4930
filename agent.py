import asyncio
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_mcp_adapters.tools import load_mcp_tools
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


PROJECT_DIR = Path(__file__).resolve().parent
SANDBOX_DIR = PROJECT_DIR / "sandbox"
SANDBOX_DIR.mkdir(exist_ok=True)
SYSTEM_PROMPT = (
    "You are a helpful agent with text-processing tools and sandboxed file "
    "tools. The text-processing tools can count words, characters, and lines; "
    "hash text; convert letter case; and validate JSON. The file tools can "
    "access only the project's sandbox directory. Combine these tools when "
    "needed to complete multi-step requests, and never claim to access files "
    "outside the sandbox."
)

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
    """Load credentials, connect to both MCP servers, and run the agent.

    The Google API key is read from ``GOOGLE_API_KEY`` in the project's
    ``.env`` file. MCP server sessions remain open for the duration of the
    interactive session so the agent can use tools from both servers.

    Raises:
        RuntimeError: If ``GOOGLE_API_KEY`` is not set in the environment or
            the project's ``.env`` file.
    """
    load_dotenv(PROJECT_DIR / ".env")
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError(
            f"GOOGLE_API_KEY is not set. Add it to {PROJECT_DIR / '.env'}."
        )

    model = ChatGoogleGenerativeAI(
        model="gemini-3.8-flash",
        google_api_key=api_key,
    )

    async with AsyncExitStack() as stack:
        tools = []
        for server_params in SERVER_PARAMS.values():
            read_stream, write_stream = await stack.enter_async_context(
                stdio_client(server_params)
            )
            session = await stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            await session.initialize()
            tools.extend(await load_mcp_tools(session))

        agent = create_agent(
            model=model,
            tools=tools,
            system_prompt=SYSTEM_PROMPT,
        )

        print("Agent ready. Type 'quit' or 'exit' to stop.")
        while True:
            try:
                user_input = input("\nYou: ").strip()
            except EOFError:
                print()
                break

            if user_input.lower() in {"quit", "exit"}:
                break
            if not user_input:
                continue

            result = await agent.ainvoke(
                {"messages": [{"role": "user", "content": user_input}]}
            )
            print(f"\nAgent: {result['messages'][-1].content}")


if __name__ == "__main__":
    asyncio.run(main())
