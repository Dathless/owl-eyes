export const active = (state) =>
  ['queued', 'collecting', 'analyzing', 'cancelling'].includes(state);
// One serial request loop, including route switches and manual reconnects.
export class Poller {
  constructor(get, receive) {
    this.get = get;
    this.receive = receive;
    this.generation = 0;
    this.pending = Promise.resolve();
  }
  subscribe(id) {
    this.stop();
    if (!id) return;
    this.id = id;
    this.failures = 0;
    const generation = this.generation;
    this.schedule(generation, 0);
  }
  schedule(generation, delay) {
    this.timer = setTimeout(() => this.tick(generation), delay);
  }
  read(id) {
    const result = this.pending.then(() => this.get(id));
    this.pending = result.catch(() => undefined);
    return result;
  }
  async tick(generation) {
    await this.pending;
    if (generation !== this.generation) return;
    const id = this.id;
    const result = await this.read(id);
    if (generation !== this.generation) return;
    this.failures = result.ok ? 0 : this.failures + 1;
    this.receive(result, id, this.failures);
    if (generation !== this.generation || result.status === 404 || result.status === 401)
      return;
    if (!result.ok || active(result.data.state))
      this.schedule(
        generation,
        result.ok ? 1000 : Math.min(8000, 1000 * 2 ** Math.min(this.failures, 3)),
      );
  }
  stop() {
    this.generation += 1;
    clearTimeout(this.timer);
    this.id = null;
  }
}
