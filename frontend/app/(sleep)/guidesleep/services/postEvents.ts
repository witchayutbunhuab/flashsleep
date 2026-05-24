type Handler = (payload?: any) => void;

class PostEvents {
  private handlers: Record<string, Handler[]> = {};

  on(event: string, handler: Handler) {
    if (!this.handlers[event]) this.handlers[event] = [];
    this.handlers[event].push(handler);
    // return an unsubscribe function
    return () => this.off(event, handler);
  }

  off(event: string, handler: Handler) {
    if (!this.handlers[event]) return;
    this.handlers[event] = this.handlers[event].filter(h => h !== handler);
    if (this.handlers[event].length === 0) {
      delete this.handlers[event];
    }
  }

  emit(event: string, payload?: any) {
    const list = this.handlers[event] || [];
    const snapshot = list.slice();
    for (const h of snapshot) {
      try {
        h(payload);
      } catch (e) {
      }
    }
  }
}

export default new PostEvents();
