import { page } from './dom.js';

const data = page ? page.dataset : {};

export const appBase = data.appBase || '/';
export const currentTrend = data.trendValue || '24h';
export const dashboardStateOwner = data.stateOwner || 'anonymous';
export const isAdmin = data.isAdmin === '1';
export const tablePageSize = 10;
