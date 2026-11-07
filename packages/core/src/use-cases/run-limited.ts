/** Runs tasks with at most `limit` in flight; results keep the input order. */
export async function runLimited<T>(tasks: ReadonlyArray<() => Promise<T>>, limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let next = 0;
  const worker = async () => {
    while (next < tasks.length) {
      const index = next++;
      results[index] = await (tasks[index] as () => Promise<T>)();
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, tasks.length)) }, worker));
  return results;
}
