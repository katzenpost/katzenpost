---
title: "Katzenpost Improvement Proposals"
linkTitle: "KIPs"
description: "The procedure for proposing improvements and protocol changes to the Katzenpost project."
categories: [""]
tags: [""]
draft: false
---

If you have an idea to change or otherwise enhance the Katzenpost project at the
protocol level, we require the proposal to be accompanied by a comprehensive and
concise text outlining the specification that clearly explains engineering
and/or cryptographic choices.

**Examples Specs:**

- [Public Key Infrastructure](/docs/specs/pki/)
- [Sphinx Cryptographic Packet Format](/docs/specs/sphinx/)

### 0. Discuss proposal with a developer

Perhaps it's useful to discuss your idea before writing anything more elaborate.
Perhaps it's already being worked on under a different name? Perhaps it had been
considered previously, but has undesirable attack vectors. It's better to solicit minor
feedback first.

### 1. Write rough draft of proposal

Once there is `N > 0` other developers who validate your idea, scribble it down
somewhere shareable. This can be in an Etherpad, Google Docs, a Nextcloud, or if
possible, ideally a `git commit` (skip to Step 3).

### 2. Solicit feedback from other developers

If you prefer to get feedback *before* your proposal is committed to eternity in
the git repo, share the URL with developers through preferred channel(s) and
discuss accordingly.

### 3. Commit KIP to monorepo

Once you are ready for your proposal to be committed to eternity in git, please
append the following "frontmatter" YAML snippet so that your

```
title: "Longer Form Explicite Name"
linkTitle: "Name"
description: ""
categories: [""]
tags: [""]
author: ["your-name"] 
version: 0
draft: true
```

The correct location to commit your KIP to is here:

```
katzenpost/docs/spec/
```

Name your file one or two words accordingly to it's title `name.md`

### Additionally

Additional concerns, steps to be added....
