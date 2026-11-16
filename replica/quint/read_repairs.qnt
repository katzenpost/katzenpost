// The replica's memory of served reads, replica/read_repair.go readRepairs:
// remember(envHash) on every read served with a box, take(envHash) on a
// courier's repair hint, oldest first out at MAX entries or after TTL.
//
// ONE_PER_HASH=false is the code at 361e6a868: remember appends a queue
// record even when the hash is already remembered, the bound counts map
// entries, and take leaves the record queued.
//
//   quint run --main=read_repairs_append --invariant=bounded replica/quint/read_repairs.qnt  # violated
//   quint run --main=read_repairs_fixed  --invariant=bounded replica/quint/read_repairs.qnt  # holds
module read_repairs {
  const ONE_PER_HASH: bool
  const MAX: int
  const TTL: int

  val HASHES = Set(1, 2, 3)
  val MAX_TIME = 8

  type Remembered = { h: int, at: int }
  type Mem = { boxes: int -> int, order: List[Remembered] }

  var mem: Mem
  var now: int

  pure def without(m: int -> int, h: int): int -> int =
    m.keys().exclude(Set(h)).mapBy(k => m.get(k))

  pure def expired(r: Remembered, t: int): bool = t - r.at > TTL

  // forgetOldest at 361e6a868: drop the head, and its map entry unless
  // the hash was remembered again since.
  pure def forgetOldest(m: Mem): Mem =
    val old = m.order.head()
    val keep = m.boxes.keys().contains(old.h) and m.boxes.get(old.h) != old.at
    { boxes: if (keep) m.boxes else without(m.boxes, old.h), order: m.order.tail() }

  pure def full(m: Mem): bool =
    if (ONE_PER_HASH) m.order.length() >= MAX else m.boxes.keys().size() >= MAX

  // The eviction loop in remember; it runs at most length(order) times.
  pure def evict(m: Mem, t: int): Mem =
    m.order.indices().fold(m, (acc, _) =>
      if (acc.order.length() > 0 and (full(acc) or expired(acc.order.head(), t))) forgetOldest(acc) else acc)

  pure def forgetHash(m: Mem, h: int): Mem =
    { boxes: without(m.boxes, h), order: m.order.select(r => r.h != h) }

  pure def remember(m: Mem, h: int, t: int): Mem =
    val m1 = if (ONE_PER_HASH) forgetHash(m, h) else m
    val m2 = evict(m1, t)
    { boxes: m2.boxes.put(h, t), order: m2.order.append({ h: h, at: t }) }

  pure def take(m: Mem, h: int): Mem =
    if (ONE_PER_HASH) forgetHash(m, h) else { ...m, boxes: without(m.boxes, h) }

  action init = all {
    mem' = { boxes: Map(), order: [] },
    now' = 0,
  }

  action doRemember(h: int): bool = all { mem' = remember(mem, h, now), now' = now }
  action doTake(h: int): bool = all { mem' = take(mem, h), now' = now }
  action tick: bool = all { now < MAX_TIME, now' = now + 1, mem' = mem }

  action step = {
    nondet h = HASHES.oneOf()
    any { doRemember(h), doTake(h), tick }
  }

  // The queue, not only the map, holds at most MAX records.
  val bounded: bool = mem.order.length() <= MAX

  // One queued record per remembered hash, and none for a forgotten one.
  val onePerHash: bool =
    mem.order.length() == mem.boxes.keys().size() and
    mem.order.indices().forall(i => mem.boxes.keys().contains(mem.order[i].h) and mem.boxes.get(mem.order[i].h) == mem.order[i].at)

  val safe: bool = bounded and onePerHash

  val atBound: bool = mem.order.length() == MAX
}

module read_repairs_append { import read_repairs(ONE_PER_HASH = false, MAX = 2, TTL = 2).* }
module read_repairs_fixed { import read_repairs(ONE_PER_HASH = true, MAX = 2, TTL = 2).* }
