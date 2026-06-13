/**
 * OAuth client management routes (Phase 2) — ADMIN ONLY.
 *
 *   POST   /clients            register a client -> { clientId, clientSecret? }
 *   GET    /clients            list clients (no secrets)
 *   GET    /clients/:clientId  one client (no secret)
 *   DELETE /clients/:clientId  remove a client
 *
 * Every route is guarded by requireAuth + requireAdmin (mounted in server.ts). The client
 * secret for confidential clients is returned exactly once, here, and never again.
 */

import { Router, Request, Response, NextFunction } from 'express';
import { validate, createClientSchema } from '../lib/validation';
import { AppError } from '../lib/errors';
import * as clientService from '../services/client.service';

const router = Router();

const h =
    (fn: (req: Request, res: Response) => Promise<void>) =>
    (req: Request, res: Response, next: NextFunction) =>
        fn(req, res).catch(next);

router.post(
    '/',
    h(async (req, res) => {
        const input = validate(createClientSchema, req.body);
        const { client, clientSecret } = await clientService.createClient(input);
        res.status(201).json({
            clientId: client.client_id,
            // Only present for confidential clients — shown ONCE.
            ...(clientSecret ? { clientSecret } : {}),
            client,
            ...(clientSecret
                ? { warning: 'Store clientSecret now — it will never be shown again.' }
                : {}),
        });
    }),
);

router.get(
    '/',
    h(async (_req, res) => {
        res.status(200).json({ clients: await clientService.listClients() });
    }),
);

router.get(
    '/:clientId',
    h(async (req, res) => {
        const client = await clientService.getPublicClient(req.params.clientId);
        if (!client) throw new AppError(404, 'not_found', 'Client not found');
        res.status(200).json({ client });
    }),
);

router.delete(
    '/:clientId',
    h(async (req, res) => {
        const deleted = await clientService.deleteClient(req.params.clientId);
        if (!deleted) throw new AppError(404, 'not_found', 'Client not found');
        res.status(200).json({ success: true });
    }),
);

export default router;
