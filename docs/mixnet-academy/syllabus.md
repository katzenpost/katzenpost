---
title: "Syllabus, Learn Mix Networks for Great Good"
linkTitle: "Syllabus"
description: ""
categories: [""]
tags: [""]
author: []
version: 0
---

(maybe the second title should be: Prevent Murder using Mathematics)

## Course Syllabus And Reading List

There are no good introductory papers on mix networks. Instead, the
approach is to read all the really important academic papers on mix
networks. These papers are roughly organized into several categories
such as:

Missing from this list are `verified shuffles`. These are specialized
mix strategies which at times are very useful for specific use cases
such as `voting`.

In a few of these mixnet sections I have included youtube videos I\'ve
made to help explain some of the fundamental mixnet concepts. As you
read these mixnet papers keep in mind that decryption mixnets have the
following attack categories:

- tagging attacks
- n-1 attacks
- compulsion attacks
- statistical disclosure attacks
- epistemic attacks

After all this mix network literature we turn to the
`Classical Packet Switching Network Literature` below in the next major
section of reading. Many of these important papers happen to not be
academic papers but rather come from industry / IETF and are RFCs. Why
read these? Aren't mixnet papers enough? Yes if you want to only
publish papers on mix networks then reading about only mix networks may
be enough.

However if you want to design real world mix network systems then
understanding the mathematical limitations of the packet switching
networking design space is extremely important! You must read about the
early Internet design mistakes to understand what not to do in your mix
network designs. In your mix network designs you must take care to avoid
such fatal conditions such as **Congestion Collapse**.

Have questions? Sit on them for a week and voraciously read papers. If
you still have questions then do feel free to ask me. We have a mailing
list and IRC channel for such things:

- https://katzenpost.network/contribute/

### Mix Network Fundamentals

- [A Brief Introduction to mix networks](https://www.youtube.com/watch?v=1VMUb47QhfE)
- [Introduction to Mix Networks and Anonymous Communication Networks](https://leastauthority.com/blog/mixnet-intro/)
- [Untraceable electronic mail, return addresses, and digital pseudonyms](https://www.freehaven.net/anonbib/cache/chaum-mix.pdf)
- [Anonymity Trilemma: Strong Anonymity, Low Bandwidth Overhead, Low Latency - Choose Two](https://eprint.iacr.org/2017/954.pdf)

### Mix Strategies

- [From a Trickle to a Flood: Active Attacks on Several Mix Types](https://www.freehaven.net/anonbib/cache/trickle02.pdf)
- [Why I'm not an Entropist](https://www.freehaven.net/anonbib/cache/entropist.pdf)
- [Sleeping dogs lie on a bed of onions but wake when mixed](https://bib.mixnetworks.org/pdf/pets2011.pdf)
- [Stop-and-Go MIXes: Providing Probabilistic Anonymity in an Open System](https://www.freehaven.net/anonbib/cache/stop-and-go.pdf)
- [Heartbeat Traffic to Counter (n-1) Attacks](https://www.freehaven.net/anonbib/cache/danezis:wpes2003.pdf)
- [Generalising Mixes](https://www.freehaven.net/anonbib/cache/diaz:pet2003.ps.gz)

### Mix Network Topology

- [Mix Network Topology](https://www.youtube.com/watch?v=bxk4H_X_OsM)
- [Impact of Network Topology on Anonymity and Overhead in Low-Latency Anonymity Networks](https://www.esat.kuleuven.be/cosic/publications/article-1230.pdf)
- [The disadvantages of free MIX routes and how to overcome them](https://www.freehaven.net/anonbib/cache/disad-free-routes.pdf)

### Compulsion Attacks And Packet Format

- [Sphinx: A Compact and Provably Secure Mix Format](https://www.freehaven.net/anonbib/cache/DBLP:conf/sp/DanezisG09.pdf)
- [Compulsion Resistant Anonymous Communications](https://www.freehaven.net/anonbib/cache/ih05-danezisclulow.pdf)
- [Forward Secure Mixes](https://www.freehaven.net/anonbib/cache/Dan:SFMix03.pdf)

Note that Jeff Burdges has designed but not completely specified a new
forward secure mix design that uses Post Quantum cryptographic ratchets.
You can learn more about this here:

- https://github.com/burdges/lake

### Statistical Disclosure Attacks and Decoy Traffic

- [Introduction to Statistical Disclosure Attacks and Defenses for Mix Networks](https://www.youtube.com/watch?v=pHLbe1JKrAQ&t=229s
- [Statistical Disclosure or Intersection Attacks on Anonymity Systems](https://www.freehaven.net/anonbib/cache/DanSer04.ps)
- [Taxonomy of Mixes and Dummy Traffic](https://www.freehaven.net/anonbib/cache/taxonomy-dummy.pdf)
- [Limits of Anonymity in Open Environments](https://www.freehaven.net/anonbib/cache/limits-open.pdf)
- [Reasoning about the Anonymity Provided by Pool Mixes that Generate Dummy Traffic](https://www.freehaven.net/anonbib/cache/pool-dummy04.pdf)

### Epistemic Attacks

- [Route Finger printing in Anonymous Communications](https://www.cl.cam.ac.uk/~rnc1/anonroute.pdf)
- [Bridging and Fingerprinting: Epistemic Attacks on Route Selection](https://www.freehaven.net/anonbib/cache/danezis-pet2008.pdf)
- [Local View Attack on Anonymous Communication](https://www.freehaven.net/anonbib/cache/esorics05-Klonowski.pdf)

## Modern Mix Network Designs

- [The Loopix Anonymity System](https://arxiv.org/pdf/1703.00536.pdf)
- [No right to remain silent: Isolating Malicious Mixes](https://eprint.iacr.org/2017/1000.pdf)
- [A Reputation System to Increase MIX-Net Reliability](https://www.freehaven.net/anonbib/cache/mix-acc.pdf)
- [Two Cents for Strong Anonymity: The Anonymous Post-office Protocol](https://eprint.iacr.org/2016/489.pdf)
- [Vuvuzela: Scalable Private Messaging Resistant to Traffic Analysis](https://www.freehaven.net/anonbib/cache/vuvuzela:sosp15.pdf)


## Classical Packet Switching Network Literature

### Congestion Control

- [RFC 896: Congestion Control in IP/TCP Internetworks](https://tools.ietf.org/html/rfc896)
- [Congestion Avoidance and Control](http://ee.lbl.gov/papers/congavoid.pdf)
- [Promoting the Use of End-to-End Congestion Control in the Internet](https://www.icir.org/floyd/papers/collapse.may99.pdf)
- [RFC5681: TCP Congestion Control](https://tools.ietf.org/html/rfc5681)

### Automatic Repeat Request Protocol Considerations

NOTE: many more papers by Milica Stojanovic about underwater acoustic
network protocols [can be found here](http://millitsa.coe.neu.edu/?q=publications):

- [Optimization of a Data Link Protocol for an Underwater Acoustic Channel](http://web.mit.edu/millitsa/www/resources/pdfs/arq.pdf)

### Router Scheduling (for general purpose computers)

- [SEDA: An Architecture for Well-Conditioned, Scalable Internet Services](http://www.sosp.org/2001/papers/welsh.pdf)

### Active Queue Management

- [Controlling Queue Delay: A modern AQM is just one piece of the solution to bufferbloat](https://dl.acm.org/ft_gateway.cfm?id=2209336&ftid=1217981&dwn=1)
- [Random Early Detection Gateways for Congestion Avoidance](http://www.icir.org/floyd/papers/early.pdf)
- [Controlled Delay Active Queue Management](https://tools.ietf.org/html/draft-ietf-aqm-codel-07)
- [Stochastic Fair Blue: A Queue Management Algorithm for Enforcing Fairness](http://www.thefengs.com/wuchang/blue/41_2.PDF)
- [RSFB: Resilient Stochastic Fair Blue algorithm](https://sites.google.com/site/cwzhangres/home/files/RSFBaResilientStochasticFairBluealgorithmagainstspoofingDDoSattacks.pdf)

## Attacks on Congestion Control

- [the TCP Daytona paper](http://cseweb.ucsd.edu/~savage/papers/CCR99.pdf)
- [Low-Rate TCP-Targeted Denial of Service Attacks (The Shrew vs. the Mice and Elephants)](http://www.cs.cornell.edu/People/egs/cornellonly/syslunch/spring04/p75-kuzmanovic.pdf)
- [Flow level detection and filtering of low-rate DDoS](http://discovery.ucl.ac.uk/1399235/2/1399235.pdf)
- [The Sniper Attack: Anonymously Deanonymizing and Disabling the Tor Network](https://www.freehaven.net/anonbib/cache/sniper14.pdf)

### Congestion Control with Explicit Signaling

NOTE: for more reading on this subject refer to [Dr. Sally Floyd's ECN reading list](http://www.icir.org/floyd/ecn.html)

- [TCP and Explicit Congestion Notification](http://www.icir.org/floyd/papers/tcp_ecn.4.pdf>
- [The Benefits of Using Explicit Congestion Notification (ECN)](https://tools.ietf.org/html/rfc8087)
- [Performance Evaluation of Explicit Congestion Notification (ECN) in IP Networks](https://tools.ietf.org/html/rfc2884)
