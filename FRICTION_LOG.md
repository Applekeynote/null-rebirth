# Build notes: what slowed this project down

These notes describe this project's development, not a benchmark of the services.

1. **An account-ready screen was not the same as model access.** The first Bedrock call was rejected while account verification was pending. The backend treated that as a blocked run. Later, a real Nova Micro response confirmed access; the 20-case acceptance test then ran against the deployed roles.
2. **A plausible plan could target the wrong repair.** In one containment test, two model proposals failed the target check. Returning the concrete rejection reason produced a valid third proposal. The allowlist and evidence check stayed strict throughout.
3. **Cleanup permissions had their own dependency.** A disposable-stack rehearsal removed permissions before deletion finished. Moving cleanup into a dedicated role allowed the rehearsal to finish. Scheduled deletion is now part of the deployment rather than a calendar note.
4. **SDK generation mattered.** The installed official MCP v2 client exposed snake_case result properties and could return a JSON text content block without structured_content. The host now handles both forms. Interop checks assert the decoded result, not merely a successful HTTP response.
5. **Transport testing needed the right environment.** Loopback requests were blocked by the development sandbox. Running the explicit localhost verification with authorized network access distinguished that restriction from an MCP failure.

What I would like next: clearer account readiness diagnostics before the first inference call, a small official end-to-end Alexa+ simulation example with explicit confirmation, and examples that show denial and retry paths alongside successful tool calls.

The current Alexa+ experience is a browser simulation. No actual Alexa account or Echo was connected.


## Reproduction detail

| Task and steps | Expected / actual | Severity | Workaround and requested improvement |
| --- | --- | --- | --- |
| Call Bedrock Converse for the first deployed diagnosis | Expected a model result; account verification blocked the request | Important | Keep the run blocked and retry after readiness is confirmed. Expose readiness diagnostics before inference. |
| Submit Nova's containment plan to the target/evidence gate | Expected the selected runbook to match the fault; two proposals did not | Important | Return the specific rejection reason and bound the retry count. Document rejection-path examples alongside success. |
| Delete a disposable CloudFormation rehearsal stack | Expected deletion to finish; its permission dependency was removed too early | Critical for this exhibition's cleanup | Retain the dedicated cleanup role until stack removal is verified. Document cleanup dependency ordering. |
| Read an official MCP v2 call_tool result | Expected a structured object; the result could be JSON text, with snake_case client fields | Important | Decode both supported result forms and assert their content. Keep version-specific examples close to the API. |
| Call the loopback MCP server from the development shell | Expected an HTTP response; the sandbox blocked the connection | Minor, local environment | Use explicitly authorized localhost network access. Report connection denial separately from protocol failure. |

These are development observations. The proposed fixes are requests, not claims that Alexa+ itself caused the SDK or local-environment issues.
