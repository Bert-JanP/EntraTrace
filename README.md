# EntraTrace

**EntraTrace** is a defensive security research tool for documenting and identifying the observable behavior of offensive tooling targeting Microsoft Entra ID.

The project builds a knowledge base around tools such as **AzureHound, AADInternals, O365Enum, PingCastle**, and others, with a focus on the network-level artifacts they generate.

## What does it track?

EntraTrace focuses on information that can be useful to defenders, including:

* 🔎 **API endpoints** — Entra ID and Microsoft Graph endpoints accessed by tooling
* 🕵️ **User agents** — HTTP user agents associated with offensive tools
* 🔐 **Authentication behavior** — Observable authentication and token-related patterns
* 🌐 **Network activity** — Requests and other network indicators
* 🛡️ **Detection opportunities** — Data that can support detection engineering, hunting, and incident response

The goal is to make offensive tooling behavior easier for defensive teams to understand and turn into actionable detections.

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

## Project Status

🚧 **Early development**

The project is actively being developed. Data, tooling coverage, and functionality will evolve over time.

Contributions, research, corrections, and additional tool analysis are welcome.

## Responsible Use

EntraTrace is intended for **defensive security research, detection engineering, threat hunting, and authorized security testing**.

Always ensure that testing and analysis is performed against environments you own or have explicit permission to assess.

## AI-Assisted Development

> 🤖 **EntraTrace is developed with the assistance of AI.** AI is used throughout the development and research process, with human review and validation of the resulting work.

## License

See [LICENSE](LICENSE) for licensing information.
