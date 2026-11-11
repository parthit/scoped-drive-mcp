import { AsyncLocalStorage } from "node:async_hooks";

export type Scheduler = (work: () => Promise<void>) => void;

const storage = new AsyncLocalStorage<Scheduler>();

const noop: Scheduler = () => undefined;

export function currentScheduler(): Scheduler {
  return storage.getStore() ?? noop;
}

export function runWithScheduler<T>(scheduler: Scheduler, fn: () => T): T {
  return storage.run(scheduler, fn);
}
