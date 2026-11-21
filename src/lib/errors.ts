export type ErrorCode =
  | 'VALIDATION_ERROR'
  | 'INVALID_JSON'
  | 'UNSUPPORTED_MEDIA_TYPE'
  | 'PAYLOAD_TOO_LARGE'
  | 'UNAUTHORIZED'
  | 'INVALID_CREDENTIALS'
  | 'INVALID_TOKEN'
  | 'TOKEN_EXPIRED'
  | 'ACCOUNT_LOCKED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'INVALID_RESET_CODE'
  | 'PURCHASE_INVALID'
  | 'PAYMENT_PENDING'
  | 'PURCHASE_ALREADY_USED'
  | 'PAYMENT_PROVIDER_UNAVAILABLE'
  | 'RATE_LIMITED'
  | 'INTERNAL_ERROR';

export interface ErrorDetail {
  field: string;
  message: string;
}

/** Operational error that is safe to show to API clients. */
export class AppError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    message: string,
    readonly details?: ErrorDetail[],
  ) {
    super(message);
    this.name = 'AppError';
  }

  static badRequest(message: string, details?: ErrorDetail[]) {
    return new AppError(400, 'VALIDATION_ERROR', message, details);
  }
  static unauthorized(message = 'Authentication required', code: ErrorCode = 'UNAUTHORIZED') {
    return new AppError(401, code, message);
  }
  static forbidden(message = 'Forbidden') {
    return new AppError(403, 'FORBIDDEN', message);
  }
  static notFound(message = 'Resource not found') {
    return new AppError(404, 'NOT_FOUND', message);
  }
  static conflict(message: string, details?: ErrorDetail[]) {
    return new AppError(409, 'CONFLICT', message, details);
  }
}
