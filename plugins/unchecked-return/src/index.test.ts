import { describe, expect, it } from 'vitest';

import { UncheckedReturnPlugin } from './index';

describe('UncheckedReturnPlugin', () => {
	const plugin = new UncheckedReturnPlugin();

	it('should have correct metadata', () => {
		expect(plugin.metadata.id).toBe('unchecked-return');
		expect(plugin.metadata.severity).toBe('HIGH');
		expect(plugin.metadata.category).toBe('UNCHECKED_RETURN');
	});

	it('should support solidity on ethereum', () => {
		expect(
			plugin.supportsContext({
				contractName: 'Test',
				sourceCode: '',
				chain: 'ethereum',
				language: 'solidity',
				compilerVersion: null,
				metadata: {},
			}),
		).toBe(true);
	});

	it('should detect unchecked .call return value', async () => {
		const vulnerableCode = `
contract Vulnerable {
    function rescue(address payable target) public {
        target.call{value: address(this).balance}("");
    }
}`;

		const findings = await plugin.analyze({
			contractName: 'Vulnerable',
			sourceCode: vulnerableCode,
			chain: 'ethereum',
			language: 'solidity',
			compilerVersion: '0.8.19',
			metadata: {},
		});

		expect(findings.length).toBe(1);
		expect(findings[0]?.pluginId).toBe('unchecked-return');
		expect(findings[0]?.codeSnippet).toContain('target.call');
	});

	it('should detect unchecked .send return value', async () => {
		const vulnerableCode = `
contract Vulnerable {
    function payout(address payable target) public {
        target.send(1 ether);
    }
}`;

		const findings = await plugin.analyze({
			contractName: 'Vulnerable',
			sourceCode: vulnerableCode,
			chain: 'ethereum',
			language: 'solidity',
			compilerVersion: '0.8.19',
			metadata: {},
		});

		expect(findings.length).toBe(1);
		expect(findings[0]?.pluginId).toBe('unchecked-return');
		expect(findings[0]?.codeSnippet).toContain('target.send');
	});

	it('should detect unchecked .delegatecall return value', async () => {
		const vulnerableCode = `
contract Vulnerable {
    function delegate(address target, bytes memory data) public {
        target.delegatecall(data);
    }
}`;

		const findings = await plugin.analyze({
			contractName: 'Vulnerable',
			sourceCode: vulnerableCode,
			chain: 'ethereum',
			language: 'solidity',
			compilerVersion: '0.8.19',
			metadata: {},
		});

		expect(findings.length).toBe(1);
		expect(findings[0]?.pluginId).toBe('unchecked-return');
		expect(findings[0]?.codeSnippet).toContain('target.delegatecall');
	});

	it('should detect captured but unchecked return value', async () => {
		const vulnerableCode = `
contract Vulnerable {
    function withdraw(uint256 amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        // success is never checked
    }
}`;

		const findings = await plugin.analyze({
			contractName: 'Vulnerable',
			sourceCode: vulnerableCode,
			chain: 'ethereum',
			language: 'solidity',
			compilerVersion: '0.8.19',
			metadata: {},
		});

		expect(findings.length).toBe(1);
		expect(findings[0]?.pluginId).toBe('unchecked-return');
	});

	it('should not flag checked return value with require', async () => {
		const safeCode = `
contract Safe {
    function withdraw(uint256 amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}`;

		const findings = await plugin.analyze({
			contractName: 'Safe',
			sourceCode: safeCode,
			chain: 'ethereum',
			language: 'solidity',
			compilerVersion: '0.8.19',
			metadata: {},
		});

		expect(findings.length).toBe(0);
	});

	it('should not flag checked return value with if', async () => {
		const safeCode = `
contract Safe {
    function withdraw(uint256 amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert("Transfer failed");
    }
}`;

		const findings = await plugin.analyze({
			contractName: 'Safe',
			sourceCode: safeCode,
			chain: 'ethereum',
			language: 'solidity',
			compilerVersion: '0.8.19',
			metadata: {},
		});

		expect(findings.length).toBe(0);
	});

	it('should not flag non-low-level calls', async () => {
		const safeCode = `
contract Safe {
    function foo(address target) public {
        target.callSomeOtherFunction();
    }
}`;

		const findings = await plugin.analyze({
			contractName: 'Safe',
			sourceCode: safeCode,
			chain: 'ethereum',
			language: 'solidity',
			compilerVersion: '0.8.19',
			metadata: {},
		});

		expect(findings.length).toBe(0);
	});
});
