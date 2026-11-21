import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def test_real_mcp_stdio_claim_and_submit():
    async def exercise():
        parameters = StdioServerParameters(
            command=sys.executable, args=[str(Path(__file__).with_name("mcp_fixture.py"))]
        )
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert {tool.name for tool in tools.tools} >= {
                    "work_list",
                    "work_claim",
                    "work_get",
                    "work_heartbeat",
                    "work_block",
                    "work_release",
                    "work_resume",
                    "work_submit",
                    "work_provision",
                    "issues_list",
                    "task_approve",
                    "github_connect_start",
                    "sources_list",
                    "contributors_list",
                }
                denied = await session.call_tool("contributor_invite", {"name": "unauthorized"})
                assert denied.isError
                claimed = await session.call_tool(
                    "work_claim", {"idempotency_key": "mcp-integration-1"}
                )
                assert not claimed.isError
                claim = json.loads(claimed.content[0].text)
                result = await session.call_tool(
                    "work_submit",
                    {
                        "task_id": claim["contract"]["contract_id"],
                        "attempt_id": claim["assignment"]["attempt_id"],
                        "generation": claim["assignment"]["generation"],
                        "pr_url": "https://github.com/alice/widget/pull/9",
                        "head_sha": "b" * 40,
                        "evidence": "Regression tests passed",
                    },
                )
                assert not result.isError, result
                assert json.loads(result.content[0].text)["assignment"]["state"] == "submitted"
                prompts = await session.list_prompts()
                assert {p.name for p in prompts.prompts} == {"contribute", "manage_product"}

    asyncio.run(exercise())


def test_real_mcp_stdio_product_manager():
    async def exercise():
        parameters = StdioServerParameters(
            command=sys.executable, args=[str(Path(__file__).with_name("mcp_fixture.py")), "--pm"]
        )
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                async def call(name, args=None):
                    result = await session.call_tool(name, args or {})
                    assert not result.isError, result
                    return result.structuredContent or json.loads(result.content[0].text)

                assert (await call("hub_identity"))["role"] == "admin"
                assert (await call("sources_list"))["result"][0]["name"] == "alice"
                task = await call(
                    "task_approve",
                    {"source": "alice", "repository": "alice/widget", "issue_number": 1},
                )
                assert (await call("task_get", {"task_id": task["task_id"]}))["approval"]
                invited = await call("contributor_invite", {"name": "friend"})
                assert invited["token"]
                await call("contributor_revoke", {"contributor_id": invited["id"]})
                names = {tool.name for tool in (await session.list_tools()).tools}
                assert {
                    "github_connect_start",
                    "github_app_install",
                    "task_dependencies_set",
                    "pr_inspect",
                } <= names
                assert not {"issue_create", "issue_update", "issue_comment"} & names

    asyncio.run(exercise())
