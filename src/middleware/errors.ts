import type { ErrorRequestHandler, RequestHandler } from 'express';
import type { Logger } from 'pino';

import { AppError } from '../lib/errors.js';

export const notFound: RequestHandler = (req, _res, next) => {
  next(AppError.notFound(`Route ${req.method} ${req.path} not found`));
};

/** Single place that turns errors into `{ error: { code, message, details?, requestId } }`. */
export const errorHandler =
  (logger: Logger, exposeInternals: boolean): ErrorRequestHandler =>
  (err: unknown, req, res, _next) => {
    let appError: AppError;
    const bodyParserType = (err as { type?: string } | null)?.type;

    if (err instanceof AppError) {
      appError = err;
    } else if (bodyParserType === 'entity.parse.failed') {
      appError = new AppError(400, 'INVALID_JSON', 'Request body is not valid JSON');
    } else if (bodyParserType === 'entity.too.large') {
      appError = new AppError(413, 'PAYLOAD_TOO_LARGE', 'Request body is too large');
    } else {
      logger.error({ err, requestId: req.id }, 'unhandled error');
      appError = new AppError(500, 'INTERNAL_ERROR', 'Something went wrong');
    }

    if (appError.status >= 500 && err instanceof AppError) logger.error({ err, requestId: req.id }, appError.message);

    res.status(appError.status).json({
      error: {
        code: appError.code,
        message: appError.message,
        ...(appError.details?.length ? { details: appError.details } : {}),
        requestId: req.id,
        ...(exposeInternals && !(err instanceof AppError) && err instanceof Error ? { debug: err.message } : {}),
      },
    });
  };
