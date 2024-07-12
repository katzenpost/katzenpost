---
generator: DocBook XSL Stylesheets V1.79.2
title: Chapter 1. Using the Katzenpost test network
---

::: chapter
::: titlepage
<div>

<div>

## []{#d5e1}Chapter 1. Using the Katzenpost test network {#chapter-1.-using-the-katzenpost-test-network .title}

</div>

</div>
:::

::: toc
**Table of Contents**

```{=html}
<dl class="toc">
```
```{=html}
<dt>
```
[[Requirements](#requirements)]{.section}
```{=html}
</dt>
```
```{=html}
<dt>
```
[[Preparing to run the container image](#install_kp)]{.section}
```{=html}
</dt>
```
```{=html}
<dt>
```
[[Operating the test mixnet](#basic-ops)]{.section}
```{=html}
</dt>
```
```{=html}
<dd>
```
```{=html}
<dl>
```
```{=html}
<dt>
```
[[Starting and monitoring the mixnet](#start-mixnet)]{.section}
```{=html}
</dt>
```
```{=html}
<dt>
```
[[Testing the mixnet](#test-mixnet)]{.section}
```{=html}
</dt>
```
```{=html}
<dt>
```
[[Shutting down the mixnet](#shutdown-mixnet)]{.section}
```{=html}
</dt>
```
```{=html}
<dt>
```
[[Uninstalling and cleaning up](#uninstall-mixnet)]{.section}
```{=html}
</dt>
```
```{=html}
</dl>
```
```{=html}
</dd>
```
```{=html}
<dt>
```
[[Network components and topology](#topology)]{.section}
```{=html}
</dt>
```
```{=html}
</dl>
```
:::

Katzenpost provides a ready-to-deploy [Docker
image](https://github.com/katzenpost/katzenpost/tree/main/docker){.link
target="_top"} for developers who need a non-production test environment
for developing and testing client applications. By running this image on
a single computer, you avoid the need to build and manage a complex
multi-node mix net. The image can also be run using
[Podman](https://podman.io/){.link target="_top"}

The test mix network includes the following components:

::: itemizedlist
-   Three directory authority
    ([PKI](https://katzenpost.network/docs/specs/pki/){.link
    target="_top"}) nodes

-   Six [mix](https://katzenpost.network/docs/specs/mixnet/){.link
    target="_top"} nodes, including one node serving also as both
    gateway and service provider

-   A ping utility
:::

::: section
::: titlepage
<div>

<div>

## []{#requirements}Requirements {#requirements .title style="clear: both"}

</div>

</div>
:::

Before running the Katzenpost docker image, make sure that the following
`<!--
software-->`{=html}
`<!--author="dwrob" timestamp="20240607T121424-0700" comment="Add minimum hardware specs?"-->`{=html}
software is installed.

::: itemizedlist
-   A [Debian GNU Linux](https://debian.org){.link target="_top"} or
    [Ubuntu](https://ubuntu.com){.link target="_top"} system

-   [Git](https://git-scm.com/){.link target="_top"}

-   [Go](https://go.dev/){.link target="_top"}

-   [GNU Make](https://www.gnu.org/software/make/){.link target="_top"}

-   [Docker](https://www.docker.com){.link target="_top"}, [Docker
    Compose](https://docs.docker.com/compose/){.link target="_top"}, and
    (optionally) [Podman](https://podman.io){.link target="_top"}

    ::: {.note style="margin-left: 0.5in; margin-right: 0.5in;"}
      -------------------------------------------------------------------------------------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
       ![\[Note\]](file:/home/usr/local/Oxygen%20XML%20Editor%2026/frameworks/docbook/css/img/note.png)  Note
                                                                                                         If both Docker and Podman are present on your system, Katzenpost uses Podman. Podman is a drop-in daemonless equivalent to Docker that does not require superuser privileges to run.
      -------------------------------------------------------------------------------------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    :::
:::

On Debian, these software requirements can be installed with the
following commands (running as superuser). [**Apt**]{.command} will pull
in the needed dependencies.

``` programlisting
# apt update
# apt install git golang make docker docker-compose podman
```
:::

::: section
::: titlepage
<div>

<div>

## []{#install_kp}Preparing to run the container image {#preparing-to-run-the-container-image .title style="clear: both"}

</div>

</div>
:::

Complete the following procedure to obtain, build, and deploy the
Katzenpost test network.

::: procedure
1.  Install the Katzenpost code repository, hosted at
    [https://github.com/katzenpost](https://github.com/katzenpost){.link
    target="_top"}. The main Katzenpost repository contains code for the
    server components as well as the docker image. Clone the repository
    with the following command (your directory location may vary):

    ``` programlisting
    ~$ git clone https://github.com/katzenpost/katzenpost.git
    ```

2.  Navigate to the new `katzenpost`{.filename} subdirectory and ensure
    that the code is up to date.

    ``` programlisting
    ~$ cd katzenpost
    ~/katzenpost$ git checkout main
    ~/katzenpost$ git pull
    ```

3.  (Optional) Create a development branch and check it out.

    ``` programlisting
    ~/katzenpost$ git checkout -b devel
    ```

4.  (Optional) If you are using Podman, complete the following steps:

    ::: procedure
    1.  Point the DOCKER_HOST environment variable at the Podman
        process.

        ``` programlisting
        $ export DOCKER_HOST=unix:///var/run/user/$(id -u)/podman/podman.sock
        ```

    2.  Set up and start the Podman server (as superuser).

        ``` programlisting
        $ podman system service -t 0 $DOCKER_HOST &
        $ systemctl --user enable --now podman.socket
        $ systemctl --user start podman.socket
        ```
    :::
:::
:::

::: section
::: titlepage
<div>

<div>

## []{#basic-ops}Operating the test mixnet {#operating-the-test-mixnet .title style="clear: both"}

</div>

</div>
:::

Navigate to `katzenpost/docker`{.filename}. The `Makefile`{.filename}
contains target operations to create, manage, and test the
self-contained Katzenpost container network. To invoke a target, run a
command with the using the following pattern:

``` programlisting
 ~/katzenpost/docker$ make target
```

Running [**make**]{.command} with no target specified returns a list of
available targets.:

::: table
[]{#d5e100}

**Table 1.1. Makefile targets**

::: table-contents
`<!---->`{=html}
`<!--author="dwrob" timestamp="20240612T164030-0700" comment="Each of the targets needs a non-trivial description, including an explanation of when you would use it and why.

Also note suggested edits."-->`{=html}

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  \[none\]                                                                                                                                                                                                                                                                                                                                         Display this list of targets.
  [**run**]{.bold}                                                                                                                                                                                                                                                                                                                                 Run the test network in the background.
  [**start**]{.bold}                                                                                                                                                                                                                                                                                                                               Run the test network in the foreground until [**Ctrl-C**]{.command}.
  [**stop**]{.bold}                                                                                                                                                                                                                                                                                                                                Stop the test network.
  [**wait**]{.bold}                                                                                                                                                                                                                                                                                                                                `<!--Wait
                                                                                                                                                                                                                                                                                                                                                                                   for the test network to have consensus.-->`{=html} `<!--author="dwrob" timestamp="20240614T163316-0700" comment="What is the difference between doing this and not doing this? Is something gated by it?"-->`{=html} Wait for the test network to have consensus.
  [**watch**]{.bold}                                                                                                                                                                                                                                                                                                                               Display live log entries until [**Ctrl-C**]{.command}.
  [**status**]{.bold}                                                                                                                                                                                                                                                                                                                              Show test network consensus status.
  [**show-latest-vote**]{.bold}                                                                                                                                                                                                                                                                                                                    Show latest consensus vote.
  [**run-ping**]{.bold}                                                                                                                                                                                                                                                                                                                            Send a ping over the test network.
  [**clean-bin**]{.bold}                                                                                                                                                                                                                                                                                                                           Stop all components and delete binaries.
  [ **`<!--clean-local-->`{=html} `<!--author="dwrob" timestamp="20240614T172928-0700" comment="These description names could be clearer. &quot;Local&quot; doesn&apos;t say much to me, and the &quot;clean&quot; should probably be &quot;clean-all&quot;, with an explanationof what &quot;all&quot; means."-->`{=html} clean-local**]{.bold}   Stop all components, delete binaries, and delete data..
  [**clean-local-dryrun**]{.bold}                                                                                                                                                                                                                                                                                                                  Show what clean-local would delete.
  [**clean**]{.bold}                                                                                                                                                                                                                                                                                                                               The above, plus cleans includes `<!--go_deps
                                                                                                                                                                                                                                                                                                                                                                                   image-->`{=html} `<!--author="dwrob" timestamp="20240614T172951-0700" comment="We need to explain what this is."-->`{=html} go_deps image.
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
:::
:::

\

::: section
::: titlepage
<div>

<div>

### []{#start-mixnet}Starting and monitoring the mixnet {#starting-and-monitoring-the-mixnet .title}

</div>

</div>
:::

Either of two command targets, [**run**]{.command} and
[**start**]{.command}, can be used to start the mix network. The first
They differ only in that [**start**]{.command} quickly detaches and runs
the network in the background, while [**run**]{.command} runs the
network in the foreground.

::: {.note style="margin-left: 0.5in; margin-right: 0.5in;"}
+:---------------------------------:+:----------------------------------+
| ![\[Note\]](file:/home/usr/loc    | Note                              |
| al/Oxygen%20XML%20Editor%2026/fra |                                   |
| meworks/docbook/css/img/note.png) |                                   |
+-----------------------------------+-----------------------------------+
|                                   | When running [**run**]{.command}  |
|                                   | or [**start**]{.command} , be     |
|                                   | aware of the following            |
|                                   | considerations:                   |
|                                   |                                   |
|                                   | ::: itemizedlist                  |
|                                   | -   If you intend to use Docker,  |
|                                   |     you need to run               |
|                                   |     [**make**]{.command} as       |
|                                   |     superuser. If you are using   |
|                                   |     [**sudo**]{.command} to       |
|                                   |     elevate your privileges, you  |
|                                   |     need to edit                  |
|                                   |     `katze                        |
|                                   | npost/docker/Makefile`{.filename} |
|                                   |     to prepend                    |
|                                   |     [**sudo**]{.command} to each  |
|                                   |     command contained in it.      |
|                                   |                                   |
|                                   | -   If you have Podman installed  |
|                                   |     on your system and you        |
|                                   |     nonetheless want to run       |
|                                   |     Docker, you can override the  |
|                                   |     default behavior by adding    |
|                                   |     the argument                  |
|                                   |     [**docker=docker**]{.command} |
|                                   |     to the command as in the      |
|                                   |     following:                    |
|                                   |                                   |
|                                   |     ``` programlisting            |
|                                   |     ~/katzenpos                   |
|                                   | t/docker$ make run docker=docker  |
|                                   |     ```                           |
|                                   | :::                               |
+-----------------------------------+-----------------------------------+
:::

The first time that you use [**run**]{.command} or
[**start**]{.command}, the docker image will be downloaded, built, and
installed. This takes several minutes.

Starting the network for the first time with [**run**]{.command} lets
you observe the installation process as command output:

``` programlisting
~/katzenpost/docker$ make run

...
<output>
...
```

Alternatively, you can install using [**start**]{.command}, which
returns you to a command prompt. You can then use [**watch**]{.command}
to view the further progress of the installation:

``` programlisting
~/katzenpost/docker$ make start
...
~/katzenpost/docker$ make watch
...
<output>
...
```

Once installation is complete, there is a further delay as the mix
servers vote and reach a consensus.

You can confirm that installation and configuration are complete by
issuing the [**status**]{.command} command from the same or another
terminal. When the network is ready for use, [**status**]{.command}
begins returning consensus information similar to the following:

``` programlisting
~/katzenpost/docker$ make status
...
00:15:15.003 NOTI state: Consensus made for epoch 1851128 with 3/3 signatures: &{Epoch: 1851128 GenesisEpoch: 1851118
...
```
:::

::: section
::: titlepage
<div>

<div>

### []{#test-mixnet}Testing the mixnet {#testing-the-mixnet .title}

</div>

</div>
:::

At this point, you should have a locally running mix network. You can
test whether it is working correctly by using [**ping**]{.command},
which launches a packet into the network and watches for a successful
reply. Run the following command:

``` programlisting
~/katzenpost/docker$ make run-ping
```

If the network is functioning properly, the resulting output contains
lines similar to the following:

``` programlisting
19:29:53.541 INFO gateway1_client: sending loop decoy
!19:29:54.108 INFO gateway1_client: sending loop decoy
19:29:54.632 INFO gateway1_client: sending loop decoy
19:29:55.160 INFO gateway1_client: sending loop decoy
!19:29:56.071 INFO gateway1_client: sending loop decoy
!19:29:59.173 INFO gateway1_client: sending loop decoy
!Success rate is 100.000000 percent 10/10)
```

lf [**ping**]{.command} fails to receive a reply, it eventually times
out with an error message. If this happens, try the command again.

::: {.note style="margin-left: 0.5in; margin-right: 0.5in;"}
  -------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
   ![\[Note\]](file:/home/usr/local/Oxygen%20XML%20Editor%2026/frameworks/docbook/css/img/note.png)  Note
                                                                                                     If you attempt use [**ping**]{.bold} too quickly after starting the mixnet, and consensus has not been reached, the utility may crash with an error message or hang indefinitely. If this happens, issue (if necessary) a [**Ctrl-C**]{.command} key sequence to abort, check the consensus status with the [**status**]{.command} command, and then retry [**ping**]{.command}.
  -------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
:::
:::

::: section
::: titlepage
<div>

<div>

### []{#shutdown-mixnet}Shutting down the mixnet {#shutting-down-the-mixnet .title}

</div>

</div>
:::

The mix network continues to run in the terminal where you started it
until you issue a [**Ctrl-C**]{.command} key sequence, or until you
issue the following command in another terminal:

``` programlisting
~/katzenpost/docker$ make stop
```

When you stop the network, the binaries and data are left in place. This
allows for a quick restart.
:::

::: section
::: titlepage
<div>

<div>

### []{#uninstall-mixnet}Uninstalling and cleaning up {#uninstalling-and-cleaning-up .title}

</div>

</div>
:::

Several command targets can be used to uninstall the Docker image and
restore your system to a clean state. The following examples demonstrate
the commands and their output.

::: itemizedlist
-   [ **`<!--clean-bin-->`{=html}
    `<!--author="dwrob" timestamp="20240628T130504-0700" comment="*make clean* requires superuser privileges. That seems strange since I installed via podman without elevated privileges. Is this a bug?  The problems seems to be with cache and code repo files."-->`{=html}
    clean-bin**]{.command}

    To stop the network and delete the compiled binaries, run the
    following command:

    ``` programlisting
    ~/katzenpost/docker$ make clean-bin
                            
    [ -e voting_mixnet ] && cd voting_mixnet && DOCKER_HOST=unix:///run/user/1000/podman/podman.sock docker-compose down --remove-orphans; rm -fv running.stamp
    Stopping voting_mixnet_auth3_1        ... done
    Stopping voting_mixnet_servicenode1_1 ... done
    Stopping voting_mixnet_metrics_1      ... done
    Stopping voting_mixnet_mix3_1         ... done
    Stopping voting_mixnet_auth2_1        ... done
    Stopping voting_mixnet_mix2_1         ... done
    Stopping voting_mixnet_gateway1_1     ... done
    Stopping voting_mixnet_auth1_1        ... done
    Stopping voting_mixnet_mix1_1         ... done
    Removing voting_mixnet_auth3_1        ... done
    Removing voting_mixnet_servicenode1_1 ... done
    Removing voting_mixnet_metrics_1      ... done
    Removing voting_mixnet_mix3_1         ... done
    Removing voting_mixnet_auth2_1        ... done
    Removing voting_mixnet_mix2_1         ... done
    Removing voting_mixnet_gateway1_1     ... done
    Removing voting_mixnet_auth1_1        ... done
    Removing voting_mixnet_mix1_1         ... done
    removed 'running.stamp'
    rm -vf ./voting_mixnet/*.alpine
    removed './voting_mixnet/echo_server.alpine'
    removed './voting_mixnet/fetch.alpine'
    removed './voting_mixnet/memspool.alpine'
    removed './voting_mixnet/panda_server.alpine'
    removed './voting_mixnet/pigeonhole.alpine'
    removed './voting_mixnet/ping.alpine'
    removed './voting_mixnet/reunion_katzenpost_server.alpine'
    removed './voting_mixnet/server.alpine'
    removed './voting_mixnet/voting.alpine'
    ```

    This command leaves in place the cryptographic keys, the state data,
    and the logs.

-   [ **`<!--clean-local-->`{=html}
    `<!--author="dwrob" timestamp="20240628T130750-0700" comment="I need more description of what this is removing.  Run/start still very quickly start the network after this clean operation."-->`{=html}
    clean-local**]{.command}

    To delete both compiled binaries and data, run the following
    command:

    ``` programlisting
    ~/katzenpost/docker$ make clean-local

    [ -e voting_mixnet ] && cd voting_mixnet && DOCKER_HOST=unix:///run/user/1000/podman/podman.sock docker-compose down --remove-orphans; rm -fv running.stamp
    Removing voting_mixnet_mix2_1         ... done
    Removing voting_mixnet_auth1_1        ... done
    Removing voting_mixnet_auth2_1        ... done
    Removing voting_mixnet_gateway1_1     ... done
    Removing voting_mixnet_mix1_1         ... done
    Removing voting_mixnet_auth3_1        ... done
    Removing voting_mixnet_mix3_1         ... done
    Removing voting_mixnet_servicenode1_1 ... done
    Removing voting_mixnet_metrics_1      ... done
    removed 'running.stamp'
    rm -vf ./voting_mixnet/*.alpine
    removed './voting_mixnet/echo_server.alpine'
    removed './voting_mixnet/fetch.alpine'
    removed './voting_mixnet/memspool.alpine'
    removed './voting_mixnet/panda_server.alpine'
    removed './voting_mixnet/pigeonhole.alpine'
    removed './voting_mixnet/reunion_katzenpost_server.alpine'
    removed './voting_mixnet/server.alpine'
    removed './voting_mixnet/voting.alpine'
    git clean -f -x voting_mixnet
    Removing voting_mixnet/
    git status .
    On branch main
    Your branch is up to date with 'origin/main'.
    ```

-   [ **`<!--clean-->`{=html}
    `<!--author="dwrob" timestamp="20240628T130820-0700" comment="Again, I need a fuller inventory. I see that a lot of repo code is removed, and the cache. We could be more descriptive. Also, as noted, there is something weird with permissions needed for this command.. It makes no sense that I can set the testnet up as a reegular user, but I need to be root to remove it"-->`{=html}
    clean**]{.command}

    To stop the the network and delete the binaries, the data, and the
    go_deps image, run the following command as superuser:

    ``` programlisting
    ~/katzenpost/docker$ sudo make clean
    ```

-   [**clean-local-dryrun**]{.command}

    ``` programlisting
    ~/katzenpost/docker$ make clean-local-dryrun
    git clean -n -x voting_mixnet
    Would remove voting_mixnet/
    ```
:::

``` programlisting
~/katzenpost/docker$ make clean
```

For a preview of the components that [**clean-local**]{.command} would
remove, without actually deleting anything, running
[**clean-local-dryrun**]{.command} generates output as follows:
:::
:::

::: section
::: titlepage
<div>

<div>

## []{#topology}Network components and topology {#network-components-and-topology .title style="clear: both"}

</div>

</div>
:::

There needs to be an interpretation of this diagram. including the ways
that the testnet differs from production network.

::: figure
[]{#d5e299}

**Figure 1.1. Test network topology**

::: figure-contents
::: mediaobject
![Test network
topology](../../../Diagrams/katzenpost-docker-net-4.png){width="405"}
:::
:::
:::

\

Discuss how to view these components, where their configuration files
are, etc.

::: table
[]{#d5e305}

**Table 1.2.  `<!--Network hosts-->`{=html}
`<!--author="dwrob" timestamp="20240617T174147-0700" comment="I will define/describe each of these component types in a separate section, because they are general and not specific to the testnet. These host types will be linked to that.

[Update: Deferring discussion of Spool.DB and User.DB until documentations for indivdual components; not relevant for Docker image. These DBs live on the Gateway host.]

[Update: adding gateway host.]"-->`{=html} Network hosts**

::: table-contents
  Host type             Identifier     IP          Port    Panda
  --------------------- -------------- ----------- ------- -------
  Directory authority   auth1          127.0.0.1   30001   
  Directory authority   auth2          127.0.0.1   30002   
  Directory authority   auth3          127.0.0.1   30003   
  Gateway node          gateway1       127.0.0.1   30004   
  Service node          servicenode1   127.0.0.1   30006   ✓
  Mix node              mix1           127.0.0.1   30008   
  Mix node              mix2           127.0.0.1   30010   
  Mix node              mix3           127.0.0.1   30012   
:::
:::

\
:::
:::
