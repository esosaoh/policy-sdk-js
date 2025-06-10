import { ManifestDigest } from "../../manifest_digest";

export function validate(payload) {
    try {
        // Parse the input payload if it's JSON
        let input;
        try {
            input = JSON.parse(payload);
        } catch {
            // If parsing fails, treat as simple string
            input = { request: payload };
        }

        const image = "busybox:1.36";
        
        try {
            const digest = ManifestDigest.getOCIManifestDigest(image);
            const result = {
                valid: true,
                message: `Digest for ${image}: ${digest}`,
            };
            return JSON.stringify(result);
        } catch (err) {
            const result = {
                valid: false,
                message: `Error getting digest for ${image}: ${err}`,
            };
            return JSON.stringify(result);
        }
    } catch (err) {
        const result = {
            valid: false,
            message: `Policy execution error: ${err}`,
        };
        return JSON.stringify(result);
    }
}