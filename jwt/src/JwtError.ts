/**
 * Represents an error related to JWT operations.
 */
export class JwtError extends Error {
	/**
	 * Creates a new JwtError instance.
	 * @param message - A human-readable message describing the error.
	 * @param innerError - An optional error object representing the root cause of the error.
	 * @param code - An optional error code to categorize the type of error.
	 */
	constructor(
		public message: string,
		public innerError?: Error,
		public code?: string
	) {
		super(message);
	}

	public toString() {
		let result = `[${this.name}] ${this.message}`;
		if (this.code) {
			result += ` (Code: ${this.code})`;
		}
		if (this.innerError) {
			result += `\nCaused by: ${this.innerError.toString()}`;
		}

		return result;
	}
}
