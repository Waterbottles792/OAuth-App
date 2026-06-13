/**
 * Shared application logger (winston). Lives in its own module so any file can import it
 * without creating a circular dependency through server.ts.
 */

import winston from 'winston';
import { loggingConfig } from '../config';

export const logger = winston.createLogger({
    level: loggingConfig.level,
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
        }),
    ],
});
