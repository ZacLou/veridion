import type {
	AnalysisContext,
	FindingResult,
	IRulePlugin,
	PluginMetadata,
} from '@veridion/scanner-types';
import { FindingSeverity } from '@veridion/shared';

const metadata: PluginMetadata = {
	id: 'unchecked-return',
	name: 'Unchecked Low-Level Call Return Value',
	version: '1.0.0',
	description:
		'Detects low-level calls (.call, .send, .delegatecall) whose return value is not checked, which can silently fail and leave the contract in an inconsistent state.',
	severity: FindingSeverity.HIGH,
	category: 'UNCHECKED_RETURN',
	chains: ['ethereum', 'polygon', 'bsc', 'avalanche', 'arbitrum', 'optimism'],
	languages: ['solidity', 'vyper'],
	tags: ['unchecked-return', 'low-level-call', 'call', 'send', 'delegatecall', 'require'],
	author: 'Veridion',
	references: [
		'https://swcregistry.io/docs/SWC-104',
		'https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/unchecked-call-return-value/',
	],
};

const LOW_LEVEL_CALL_PATTERN = /\.(call|send|delegatecall)\s*(?:\{[^}]*\})?\s*\(/;

/**
 * Heuristic: does the source contain a check for the given variable name?
 */
function isReturnValueChecked(source: string, varName: string): boolean {
	const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
	const checkPatterns = [
		new RegExp(`require\\s*\\(\\s*${escaped}\\s*`, ''),
		new RegExp(`require\\s*\\(\\s*!\\s*${escaped}\\s*`, ''),
		new RegExp(`assert\\s*\\(\\s*${escaped}\\s*`, ''),
		new RegExp(`if\\s*\\(\\s*!?\\s*${escaped}\\s*`, ''),
	];
	return checkPatterns.some((pattern) => pattern.test(source));
}

/**
 * Extract the variable name from a tuple assignment pattern like
 * `(bool success, ) = addr.call{value: 1}("");`
 */
function extractAssignedBoolVar(line: string): string | null {
	const match = line.match(/\(\s*bool\s+(\w+)\s*,?\s*\)\s*=/);
	return match?.[1] ?? null;
}

/**
 * Extract the variable name from a single-variable assignment like
 * `bool sent = addr.send(amount);` or `sent = addr.send(amount);`
 */
function extractAssignedSingleVar(line: string): string | null {
	const match = line.match(/(?:\b\w+\s+)?(\w+)\s*=(?!=)/);
	return match?.[1] ?? null;
}

export class UncheckedReturnPlugin implements IRulePlugin {
	readonly metadata = metadata;

	async initialize(_config?: Record<string, unknown>): Promise<void> {
		// noop
	}

	// eslint-disable-next-line @typescript-eslint/require-await
	async analyze(context: AnalysisContext): Promise<FindingResult[]> {
		const findings: FindingResult[] = [];
		const lines = context.sourceCode.split('\n');

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (!line) continue;

			const callMatch = line.match(LOW_LEVEL_CALL_PATTERN);
			if (!callMatch) continue;

			const callType = callMatch[1] as 'call' | 'send' | 'delegatecall';

			// Case 1: return value captured in a tuple assignment.
			// Example: (bool success, ) = addr.call{value: amount}("");
			const tupleVar = extractAssignedBoolVar(line);
			if (tupleVar) {
				if (!isReturnValueChecked(context.sourceCode, tupleVar)) {
					findings.push(this.createFinding(context, i + 1, line, callType, tupleVar));
				}
				continue;
			}

			// Case 2: return value assigned to a single variable.
			// Example: bool sent = addr.send(amount);
			const singleVar = extractAssignedSingleVar(line);
			if (singleVar) {
				if (!isReturnValueChecked(context.sourceCode, singleVar)) {
					findings.push(this.createFinding(context, i + 1, line, callType, singleVar));
				}
				continue;
			}

			// Case 3: standalone call without capturing the return value.
			// Example: addr.call{value: amount}("");
			findings.push(this.createFinding(context, i + 1, line, callType));
		}

		return findings;
	}

	getFixRecommendation(finding: FindingResult): string {
		return `To fix the unchecked return value at ${finding.filePath}:${finding.lineStart}:

1. Capture the boolean returned by the low-level call.
2. Validate it with \`require(success)\` before proceeding.

Example fix:
\`\`\`solidity
function withdraw(uint256 amount) public {
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
\`\`\``;
	}

	supportsContext(context: AnalysisContext): boolean {
		return (
			this.metadata.chains.includes(context.chain) &&
			this.metadata.languages.includes(context.language)
		);
	}

	private createFinding(
		context: AnalysisContext,
		lineNumber: number,
		line: string,
		callType: string,
		varName?: string,
	): FindingResult {
		const description = varName
			? `Low-level \`.${callType}()\` return value is captured in \`${varName}\` but never checked. If the call fails, execution continues silently.`
			: `Low-level \`.${callType}()\` is performed without checking its return value. If the call fails, execution continues silently.`;

		return {
			pluginId: this.metadata.id,
			title: 'Unchecked Low-Level Call Return Value',
			description,
			severity: this.metadata.severity,
			filePath: `${context.contractName}.sol`,
			lineStart: lineNumber,
			lineEnd: lineNumber,
			codeSnippet: line.trim(),
			recommendation:
				'Capture the boolean returned by the call and enforce it with require(success), or use a safer transfer pattern.',
			confidence: 0.9,
			references: this.metadata.references ?? [],
		};
	}
}
