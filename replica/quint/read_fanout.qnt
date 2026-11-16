// A read sent to a box's two shard holders, as the courier serves it.
//
// Models courier/server/plugin.go: CacheReply (store a holder's answer,
// decide a repair hint) and handleOldMessage (what a client poll is
// served), and replica/read_repair.go repairFromHint (the hinted holder
// re-replicates the box). The client does not retry on box-not-found
// (NoRetryOnBoxIDNotFound), so the first non-ACK answer is final.
//
// Not modelled: SURBs, encryption, other error codes, more than one read.
//
//   quint run --main=read_fanout_direct --invariant=noFalseMissingBox replica/quint/read_fanout.qnt  # violated
//   quint run --main=read_fanout_hold   --invariant=noFalseMissingBox replica/quint/read_fanout.qnt  # holds
//   quint run --main=read_fanout_hold   --invariant=safe replica/quint/read_fanout.qnt  # violated: tombstone
//   quint run --main=read_fanout_fixed  --invariant=safe replica/quint/read_fanout.qnt  # holds
module read_fanout {
  // The courier holds a box-not-found while the other holder is silent.
  const HOLD: bool
  // A tombstone from the other holder supersedes a box-not-found, as a
  // stored box does.
  const TOMBSTONE_WINS: bool

  type Answer = Found | Tomb | Missing
  type Slot = Empty | Got(Answer)
  type Result = Pending | Served(Answer)

  val HOLDERS = Set(0, 1)

  var orig: int -> Answer   // what each holder stored when the read was sent
  var store: int -> Answer  // what each holder stores now
  var slots: int -> Slot    // the courier's cached reply per holder
  var result: Result        // what the client was served
  var holdExpired: bool     // notFoundHoldWindow has passed
  var hintTo: int           // -1 until the courier sends a repair hint

  pure def holds(a: Answer): bool = a == Found or a == Tomb

  // handleOldMessage: the holder index whose reply a poll for r serves.
  pure def servedIndex(slots: int -> Slot, r: int, tombWins: bool): int =
    val other = slots.get(1 - r)
    match slots.get(r) {
      | Empty => 1 - r
      | Got(a) =>
        if (a == Missing and (other == Got(Found) or (tombWins and other == Got(Tomb)))) 1 - r else r
    }

  // The answer a poll for r is served, or Empty for an ACK.
  pure def serve(slots: int -> Slot, r: int, hold: bool, expired: bool, tombWins: bool): Slot =
    val i = servedIndex(slots, r, tombWins)
    val held = hold and slots.get(i) == Got(Missing) and slots.get(1 - i) == Empty and not(expired)
    if (held) Empty else slots.get(i)

  // repairHintTarget: the holder with the box when the other answered
  // box-not-found, or -1.
  pure def hintTarget(slots: int -> Slot): int =
    val t = HOLDERS.filter(h => match slots.get(h) {
      | Got(a) => holds(a) and slots.get(1 - h) == Got(Missing)
      | Empty => false
    })
    if (t.size() == 1) t.getOnlyElement() else -1

  action init = {
    nondet a0 = Set(Found, Tomb, Missing).oneOf()
    nondet a1 = Set(Found, Tomb, Missing).oneOf()
    val st = Map(0 -> a0, 1 -> a1)
    all {
      orig' = st,
      store' = st,
      slots' = HOLDERS.mapBy(_ => Empty),
      result' = Pending,
      holdExpired' = false,
      hintTo' = -1,
    }
  }

  // A holder's reply reaches the courier (CacheReply).
  action holderAnswers(h: int): bool = all {
    slots.get(h) == Empty,
    val s2 = slots.set(h, Got(store.get(h)))
    all {
      slots' = s2,
      hintTo' = if (hintTo == -1) hintTarget(s2) else hintTo,
    },
    orig' = orig, store' = store, result' = result, holdExpired' = holdExpired,
  }

  // The client polls for reply index r and is served a payload.
  action clientPoll(r: int): bool = {
    val s = serve(slots, r, HOLD, holdExpired, TOMBSTONE_WINS)
    all {
      result == Pending,
      s != Empty,
      result' = match s { | Got(a) => Served(a) | Empty => Pending },
      orig' = orig, store' = store, slots' = slots, holdExpired' = holdExpired, hintTo' = hintTo,
    }
  }

  action expireHold: bool = all {
    not(holdExpired),
    holdExpired' = true,
    orig' = orig, store' = store, slots' = slots, result' = result, hintTo' = hintTo,
  }

  // The hinted holder replicates its copy to its shard peer.
  action repair: bool = all {
    hintTo != -1,
    store.get(1 - hintTo) == Missing,
    store' = store.set(1 - hintTo, store.get(hintTo)),
    orig' = orig, slots' = slots, result' = result, holdExpired' = holdExpired, hintTo' = hintTo,
  }

  action step = {
    nondet h = HOLDERS.oneOf()
    any { holderAnswers(h), clientPoll(h), expireHold, repair }
  }

  // A box-not-found is served only if neither holder had the box, or
  // the hold window ran out before the other holder answered.
  val noFalseMissing: bool =
    result == Served(Missing) implies (HOLDERS.forall(h => orig.get(h) == Missing) or holdExpired)

  // The same, for a stored box only (the case the review raised).
  val noFalseMissingBox: bool =
    result == Served(Missing) implies (HOLDERS.forall(h => orig.get(h) != Found) or holdExpired)

  // A hint goes only to a holder that served the box, for a peer that
  // answered box-not-found.
  val hintSound: bool =
    hintTo != -1 implies (holds(orig.get(hintTo)) and orig.get(1 - hintTo) == Missing)

  // Once both holders answered and disagree, a hint was sent.
  val hintSent: bool =
    hintTarget(slots) != -1 implies hintTo != -1

  val safe: bool = noFalseMissing and hintSound and hintSent

  // Witnesses: a holder missing the box ends up with it; a stored box is served.
  val repaired: bool = HOLDERS.exists(h => orig.get(h) == Missing and holds(store.get(h)))
  val servedFound: bool = result == Served(Found)
}

// abd9d9da5: reads go to both holders, no hold.
module read_fanout_direct { import read_fanout(HOLD = false, TOMBSTONE_WINS = false).* }
// 531648aa0: hold an early box-not-found.
module read_fanout_hold { import read_fanout(HOLD = true, TOMBSTONE_WINS = false).* }
// A tombstone also supersedes a box-not-found.
module read_fanout_fixed { import read_fanout(HOLD = true, TOMBSTONE_WINS = true).* }
