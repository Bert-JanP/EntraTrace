# EntraTrace

**EntraTrace** is a defensive security research tool for documenting and identifying the observable behavior of offensive tooling targeting Microsoft Entra ID.

The project builds a automatic knowledge base around tools such as **AzureHound, AADInternals, O365Enum, PingCastle**, and others, with a focus on the UserAgent and API artifacts they generate.

## Project Status

🚧 **Early development**

The project is actively being developed. Data, tooling coverage, and functionality will evolve over time.

Contributions, research, corrections, and additional tool analysis are welcome.

## What does it track?

EntraTrace focuses on information that can be useful to defenders, including:

* 🔎 **API endpoints** — Microsoft Graph, Azure AD Graph and other API endpoints accessed by tooling
* 🕵️ **User agents** — HTTP user agents associated with offensive tools
* 🛡️ **Detection opportunities** — Data that can support detection engineering, hunting, and incident response

The goal is to make offensive tooling behavior easier for defensive teams to understand and turn into actionable information.

## Tool Profiles

<!-- TOOL_PROFILE_TABLE_START -->
| Tool | Unique APIs | Unique API calls | UserAgents |
| --- | --- | --- | --- |
| [aadinternals](Profiles/aadinternals.yaml) | 4 | 110 | 18 |
| [AzureHound](Profiles/azurehound.yaml) | 2 | 28 | 0 |
| [BARK](Profiles/bark.yaml) | 3 | 77 | 0 |
| [GraphSpy](Profiles/graphspy.yaml) | 2 | 38 | 2 |
| [MFASweep](Profiles/mfasweep.yaml) | 4 | 17 | 11 |
| [MicroBurst](Profiles/microburst.yaml) | 3 | 78 | 0 |
| [MSOLSpray](Profiles/msolspray.yaml) | 1 | 1 | 0 |
| [o365enum](Profiles/o365enum.yaml) | 1 | 1 | 2 |
| [pingcastle](Profiles/pingcastle.yaml) | 3 | 14 | 1 |
| [ROADtools](Profiles/roadtools.yaml) | 4 | 434 | 7 |
| [Stormspotter](Profiles/stormspotter.yaml) | 3 | 4 | 0 |
| [TeamFiltration](Profiles/teamfiltration.yaml) | 3 | 62 | 2 |
| [TokenTactics](Profiles/tokentactics.yaml) | 4 | 8 | 16 |
<!-- TOOL_PROFILE_TABLE_END -->

## Why?

Offensive security tools are frequently used to assess and attack identity environments. Understanding **how those tools interact with Entra ID** can help defenders identify their use, investigate suspicious activity, and improve detection coverage.

EntraTrace aims to bridge the gap between offensive tooling research and defensive security operations.

## Use Cases

EntraTrace can be used to:

* Build detections for known offensive security tools
* Develop Microsoft Sentinel / SIEM hunting queries
* Investigate suspicious Entra ID and Microsoft Graph activity
* Identify tooling during incident response
* Research the behavior of offensive identity tooling
* Improve defensive visibility into identity attack techniques

## AI-Assisted Development

> 🤖 **EntraTrace is developed with the assistance of AI.** AI is used throughout the development and research process, with human review and validation of the resulting work.

## Local Deployment

The repository is updated daily, but local deployment is supported. To run locally from the repository root with Python. Use the built-in help output to confirm the available options before running them.

⚠️ - Running the script locally may result in security alerts as repos containing offensive tools are downloaded locally to extract the information needed to create a profile.

```python
# Extract API behavior from a repo or refresh all profile entries
python .\Scripts\ExtractToolBehavior.py --all-profiles --output-dir .\Profiles

# Export tool user agents from YAML profiles into a CSV
python .\Scripts\SummarizeUserAgents.py --profiles-dir .\Profiles --output .\Indicator Lists\UserAgents.csv
```

- `SummarizeUserAgents.py` exports user-agent data from profile YAML files into a hunting CSV.
- `ExtractToolBehavior.py` reads repository URLs from `Profiles\Tools.txt` when present, and otherwise falls back to every `repository_url` found in the YAML profile files in the output directory.
- Run either script with `-h` or `--help` to view the full parameter set and behavior.

## Related Content
- [Investigating Microsoft Graph Activity Logs](https://kqlquery.com/posts/graphactivitylogs/)
- [GraphApiAuditEvents: The new Graph API Logs](https://kqlquery.com/posts/graphapiauditevents/)
- [Detect threats using Microsoft Graph activity logs - Part 1](https://cloudbrothers.info/detect-threats-microsoft-graph-logs-part-1/) by Fabian Bader
- [Detect threats using Microsoft Graph activity logs - Part 2](https://cloudbrothers.info/en/detect-threats-microsoft-graph-logs-part-2/) by Fabian Bader
- [Detect threats using GraphAPIAuditEvents - Part 3](https://cloudbrothers.info/en/detect-threats-graphapiauditevents-part-3/) by Fabian Bader
- [Everything you need to know about the MicrosoftGraphActivityLogs](https://www.invictus-ir.com/news/everything-you-need-to-know-about-the-microsoftgraphactivitylogs) by Invictus IR
- [The Missing Link: AADGraphActivityLogs Finally Arrives](https://www.invictus-ir.com/news/the-missing-link-aadgraphactivitylogs-finally-arrives) by Invictus IR

## License

See [LICENSE](./LICENCE) for licensing information.
