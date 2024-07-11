```{=html}
<?xml-model href="http://docbook.org/xml/5.1/rng/docbook.rng" schematypens="http://relaxng.org/ns/structure/1.0" ?>
```
`<chapter xmlns="http://docbook.org/ns/docbook" xmlns:xlink="http://www.w3.org/1999/xlink" version="5.1">`{=html}
```{=html}
<title>
```
Using the Katzenpost test network
```{=html}
</title>
```
`<!--

This is a test comment.

-->`{=html}
```{=html}
<para>
```
Katzenpost provides a ready-to-deploy
`<link xlink:href="https://github.com/katzenpost/katzenpost/tree/main/docker">`{=html}Docker
image`</link>`{=html} for developers who need a non-production test
environment for developing and testing client applications. By running
this image on a single computer, you avoid the need to build and manage
a complex multi-node mix net. The image can also be run using
`<link xlink:href="https://podman.io/">`{=html}Podman`</link>`{=html}
```{=html}
</para>
```
```{=html}
<para>
```
The test mix network includes the following components:
```{=html}
</para>
```
```{=html}
<itemizedlist>
```
`<listitem>`{=html}
```{=html}
<para>
```
Three directory authority
(`<link xlink:href="https://katzenpost.network/docs/specs/pki/">`{=html}PKI`</link>`{=html})
nodes
```{=html}
</para>
```
`</listitem>`{=html} `<listitem>`{=html}
```{=html}
<para>
```
Six
`<link xlink:href="https://katzenpost.network/docs/specs/mixnet/">`{=html}mix`</link>`{=html}
nodes, including one node serving also as both gateway and service
provider.
```{=html}
</para>
```
`</listitem>`{=html} `<listitem>`{=html}
```{=html}
<para>
```
```{=html}
<?oxy_comment_start author="dwrob" timestamp="20240126T230431-0800" comment="What is there other than ping? Is thie ping called by &quot;make run-ping&quot; the same as the regular KP ping? Katzen should not be documented in this chapter, because it is not specific to the testnet. However, we can link from here to its documentation if we like." ?>
```
Two chat applications
```{=html}
<?oxy_comment_end ?>
```
```{=html}
</para>
```
`</listitem>`{=html}
```{=html}
</itemizedlist>
```
::: {.section xml:id="requirements"}
```{=html}
<title xml:id="requirements.title">
```
Requirements
```{=html}
</title>
```
```{=html}
<para>
```
Before running the Katzenpost docker image, make sure that the following
```{=html}
<?oxy_comment_start author="dwrob" timestamp="20240607T121424-0700" comment="Add minimum hardware specs?" ?>
```
software
```{=html}
<?oxy_comment_end ?>
```
is installed.
```{=html}
</para>
```
```{=html}
<itemizedlist>
```
`<listitem>`{=html}
```{=html}
<para>
```
A `<link xlink:href="https://debian.org">`{=html}Debian GNU
Linux`</link>`{=html} or
`<link xlink:href="https://ubuntu.com">`{=html}Ubuntu`</link>`{=html}
system
```{=html}
</para>
```
`</listitem>`{=html} `<listitem>`{=html}
```{=html}
<para>
```
`<link xlink:href="https://git-scm.com/">`{=html}Git`</link>`{=html}
```{=html}
</para>
```
`</listitem>`{=html} `<listitem>`{=html}
```{=html}
<para>
```
`<link xlink:href="https://go.dev/">`{=html}Go`</link>`{=html}
```{=html}
</para>
```
`</listitem>`{=html} `<listitem>`{=html}
```{=html}
<para>
```
`<link xlink:href="https://www.gnu.org/software/make/">`{=html}GNU
Make`</link>`{=html}
```{=html}
</para>
```
`</listitem>`{=html} `<listitem>`{=html}
```{=html}
<para>
```
`<link xlink:href="https://www.docker.com">`{=html}Docker`</link>`{=html},
`<link xlink:href="https://docs.docker.com/compose/">`{=html}Docker
Compose`</link>`{=html}, and (optionally)
`<link xlink:href="https://podman.io">`{=html}Podman`</link>`{=html}
```{=html}
</para>
```
```{=html}
<note>
```
```{=html}
<para>
```
If both Docker and Podman are present on your system, Katzenpost uses
Podman. Podman is a drop-in daemonless equivalent to Docker that does
not require superuser privileges to run.
```{=html}
</para>
```
```{=html}
</note>
```
`</listitem>`{=html}
```{=html}
</itemizedlist>
```
```{=html}
<para>
```
On Debian, these software requirements can be installed with the
following commands (running as superuser).
`<command>`{=html}Apt`</command>`{=html} will pull in the needed
dependencies.
```{=html}
</para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\# `</prompt>`{=html}`<command>`{=html}apt
update`</command>`{=html} `<prompt>`{=html}\#
`</prompt>`{=html}`<command>`{=html}apt install git golang make docker
docker-compose podman`</command>`{=html}
```{=html}
</programlisting>
```
:::

::: {.section xml:id="install_kp"}
```{=html}
<title xml:id="install_kp.title">
```
Preparing to run the container image
```{=html}
</title>
```
```{=html}
<para>
```
Complete the following procedure to obtain, build, and deploy the
Katzenpost test network.
```{=html}
</para>
```
```{=html}
<procedure>
```
`<step>`{=html}
```{=html}
<para>
```
Install the Katzenpost code repository, hosted at
`<link xlink:href="https://github.com/katzenpost">`{=html}`</link>`{=html}.
The main Katzenpost repository contains code for the server components
as well as the docker image. Clone the repository with the following
command (your directory location may vary):
```{=html}
</para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\~\$ `</prompt>`{=html}`<command>`{=html}git clone
https://github.com/katzenpost/katzenpost.git`</command>`{=html}
```{=html}
</programlisting>
```
`</step>`{=html} `<step>`{=html}
```{=html}
<para>
```
Navigate to the new `<filename>`{=html}katzenpost`</filename>`{=html}
subdirectory and ensure that the code is up to date.
```{=html}
<programlisting>
```
`<prompt>`{=html}\~\$ `</prompt>`{=html}`<command>`{=html}cd
katzenpost`</command>`{=html} `<prompt>`{=html}\~/katzenpost\$
`</prompt>`{=html}`<command>`{=html}git checkout main`</command>`{=html}
`<prompt>`{=html}\~/katzenpost\$ `</prompt>`{=html}`<command>`{=html}git
pull`</command>`{=html}
```{=html}
</programlisting>
```
```{=html}
</para>
```
`</step>`{=html} `<step>`{=html}
```{=html}
<para>
```
(Optional) Create a development branch and check it out.
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost\$ `</prompt>`{=html}`<command>`{=html}git
checkout -b devel`</command>`{=html}
```{=html}
</programlisting>
```
```{=html}
</para>
```
`</step>`{=html} `<step>`{=html}
```{=html}
<para>
```
(Optional) If you are using Podman, complete the following steps:
```{=html}
</para>
```
```{=html}
<procedure>
```
`<step>`{=html}
```{=html}
<para>
```
Point the DOCKER_HOST environment variable at the Podman process.
```{=html}
</para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\$ `</prompt>`{=html}`<command>`{=html}export
DOCKER_HOST=unix:///var/run/user/\$(id
-u)/podman/podman.sock`</command>`{=html}
```{=html}
</programlisting>
```
`</step>`{=html} `<step>`{=html}
```{=html}
<para>
```
Set up and start the Podman server (as superuser).
```{=html}
</para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\$ `</prompt>`{=html}`<command>`{=html}podman system
service -t 0 \$DOCKER_HOST &`</command>`{=html} `<prompt>`{=html}\$
`</prompt>`{=html}`<command>`{=html}systemctl \--user enable \--now
podman.socket`</command>`{=html}
```{=html}
<?oxy_comment_start author="dwrob" timestamp="20240426T163148-0700" comment="This was not specified in prior documentation, but I had to do it.  Maybe the other system command is unnecessary/useless." ?>
```
`<prompt>`{=html}\$ `</prompt>`{=html}`<command>`{=html}systemctl
\--user start podman.socket`</command>`{=html}
```{=html}
<?oxy_comment_end ?>
```
```{=html}
</programlisting>
```
`</step>`{=html}
```{=html}
</procedure>
```
`</step>`{=html}
```{=html}
</procedure>
```
:::

::: {.section xml:id="basic-ops"}
```{=html}
<title xml:id="basic-ops.title">
```
Operating the test mixnet
```{=html}
</title>
```
```{=html}
<para>
```
Navigate to `<filename>`{=html}katzenpost/docker`</filename>`{=html}.
The `<filename>`{=html}Makefile`</filename>`{=html} contains target
operations to create, manage, and test the self-contained Katzenpost
container network. To invoke a target, run a command with the using the
following pattern:
```{=html}
</para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}make`<replaceable>`{=html}
target`</replaceable>`{=html}`</command>`{=html}
```{=html}
</programlisting>
```
```{=html}
<para>
```
Running `<command>`{=html}make`</command>`{=html} with no target
specified returns a list of available targets.
```{=html}
<?oxy_delete author="dwrob" timestamp="20240614T161955-0700" content=" These include the following" ?>
```
:
```{=html}
</para>
```
```{=html}
<?oxy_custom_start type="oxy_content_highlight" color="255,255,0" ?>
```
```{=html}
<table>
```
```{=html}
<?oxy_comment_start author="dwrob" timestamp="20240612T164030-0700" comment="Each of the targets needs a non-trivial description, including an explanation of when you would use it and why.

Also note suggested edits." ?>
```
```{=html}
<title>
```
Makefile targets
```{=html}
<?oxy_comment_end ?>
```
```{=html}
</title>
```
`<tgroup cols="2">`{=html}
```{=html}
<tbody>
```
`<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
\[none\]
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Display this list of targets.
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
`<emphasis role="bold">`{=html}run`</emphasis>`{=html}
```{=html}
</para>
```
`</entry>`{=html}
```{=html}
<?oxy_comment_start author="dwrob" timestamp="20240614T163648-0700" comment="These run commands are backwards.

They also should be given less ambiguous names, maybe run-background and run-foreground." ?>
```
`<entry>`{=html}
```{=html}
<para>
```
Run the test
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T160754-0700" ?>
```
```{=html}
<?oxy_insert_end ?>
```
net
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T160759-0700" ?>
```
work
```{=html}
<?oxy_insert_end ?>
```
in the background.
```{=html}
</para>
```
`</entry>`{=html}
```{=html}
<?oxy_comment_end ?>
```
`</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
`<emphasis role="bold">`{=html}start`</emphasis>`{=html}
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Run the test
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T160908-0700" ?>
```
```{=html}
<?oxy_insert_end ?>
```
net
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T160911-0700" ?>
```
work
```{=html}
<?oxy_insert_end ?>
```
in the foreground
```{=html}
<?oxy_delete author="dwrob" timestamp="20240614T161113-0700" content="," ?>
```
until
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T160728-0700" ?>
```
`<command>`{=html}Ctrl-C`</command>`{=html}
```{=html}
<?oxy_insert_end ?>
```
```{=html}
<?oxy_delete author="dwrob" timestamp="20240614T160728-0700" content="ctrl-C" ?>
```
.
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
`<emphasis role="bold">`{=html}stop`</emphasis>`{=html}
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Stop the test
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T161000-0700" ?>
```
```{=html}
<?oxy_insert_end ?>
```
net
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T161005-0700" ?>
```
work
```{=html}
<?oxy_insert_end ?>
```
.
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
`<emphasis role="bold">`{=html}wait`</emphasis>`{=html}
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
```{=html}
<?oxy_comment_start author="dwrob" timestamp="20240614T163316-0700" comment="What is the difference between doing this and not doing this? Is something gated by it?" ?>
```
Wait for the test
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T160743-0700" ?>
```
```{=html}
<?oxy_insert_end ?>
```
net
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T160747-0700" ?>
```
work
```{=html}
<?oxy_insert_end ?>
```
to have consensus.
```{=html}
<?oxy_comment_end ?>
```
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html}
`<entry>`{=html}`<emphasis role="bold">`{=html}watch`</emphasis>`{=html}`</entry>`{=html}
`<entry>`{=html}
```{=html}
<para>
```
Display live log entries
```{=html}
<?oxy_delete author="dwrob" timestamp="20240614T160652-0700" content="," ?>
```
until
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T160721-0700" ?>
```
`<command>`{=html}Ctrl-C`</command>`{=html}.
```{=html}
<?oxy_insert_end ?>
```
```{=html}
<?oxy_delete author="dwrob" timestamp="20240614T160706-0700" content="ctrl-C." ?>
```
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
`<emphasis role="bold">`{=html}status`</emphasis>`{=html}
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Show test
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T161017-0700" ?>
```
```{=html}
<?oxy_insert_end ?>
```
net
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T161025-0700" ?>
```
work
```{=html}
<?oxy_insert_end ?>
```
consensus status.
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
`<emphasis role="bold">`{=html}show-latest-vote`</emphasis>`{=html}
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
```{=html}
<?oxy_delete author="dwrob" timestamp="20240614T161143-0700" content="Does what it says." ?>
```
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T161143-0700" ?>
```
Show latest consensus vote.
```{=html}
<?oxy_insert_end ?>
```
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
`<emphasis role="bold">`{=html}run-ping`</emphasis>`{=html}
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}Send a ping over the test
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T161037-0700" ?>
```
```{=html}
<?oxy_insert_end ?>
```
net
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T161041-0700" ?>
```
work
```{=html}
<?oxy_insert_end ?>
```
.`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
`<emphasis role="bold">`{=html}clean-bin`</emphasis>`{=html}
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Stop
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T160500-0700" ?>
```
all components
```{=html}
<?oxy_insert_end ?>
```
```{=html}
<?oxy_delete author="dwrob" timestamp="20240614T160500-0700" content="," ?>
```
and delete
```{=html}
<?oxy_delete author="dwrob" timestamp="20240614T160517-0700" content="compiled " ?>
```
binaries.
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
`<emphasis role="bold">`{=html}
```{=html}
<?oxy_comment_start author="dwrob" timestamp="20240614T172928-0700" comment="These description names could be clearer. &quot;Local&quot; doesn&#39;t say much to me, and the &quot;clean&quot; should probably be &quot;clean-all&quot;, with an explanationof what &quot;all&quot; means." ?>
```
clean-local
```{=html}
<?oxy_comment_end ?>
```
`</emphasis>`{=html}
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Stop
```{=html}
<?oxy_delete author="dwrob" timestamp="20240614T160525-0700" content="," ?>
```
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T160536-0700" ?>
```
all components, delete binaries,
```{=html}
<?oxy_insert_end ?>
```
and delete data
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T160612-0700" ?>
```
.
```{=html}
<?oxy_insert_end ?>
```
```{=html}
<?oxy_delete author="dwrob" timestamp="20240614T160608-0700" content=" and binaries" ?>
```
.
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
`<emphasis role="bold">`{=html}clean-local-dryrun`</emphasis>`{=html}
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Show what clean-local would delete.
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
`<emphasis role="bold">`{=html}clean`</emphasis>`{=html}
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
The above, plus cleans includes
```{=html}
<?oxy_comment_start author="dwrob" timestamp="20240614T172951-0700" comment="We need to explain what this is." ?>
```
go_deps image
```{=html}
<?oxy_comment_end ?>
```
```{=html}
<?oxy_insert_start author="dwrob" timestamp="20240614T160641-0700" ?>
```
.
```{=html}
<?oxy_insert_end ?>
```
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html}
```{=html}
</tbody>
```
`</tgroup>`{=html}
```{=html}
<?oxy_custom_end ?>
```
```{=html}
</table>
```
::: {.section xml:id="start-mixnet"}
```{=html}
<title xml:id="start-mixnet.title">
```
Starting and monitoring the mixnet
```{=html}
</title>
```
```{=html}
<para>
```
Either of two command targets, `<command>`{=html}run`</command>`{=html}
and `<command>`{=html}start`</command>`{=html}, can be used to start the
mix network. The first They differ only in that
`<command>`{=html}start`</command>`{=html} quickly detaches and runs the
network in the background, while
`<command>`{=html}run`</command>`{=html} runs the network in the
foreground.
```{=html}
</para>
```
```{=html}
<note>
```
```{=html}
<para>
```
When running `<command>`{=html}run`</command>`{=html} or
`<command>`{=html}start`</command>`{=html} , be aware of the following
considerations:
```{=html}
</para>
```
```{=html}
<itemizedlist>
```
`<listitem>`{=html}
```{=html}
<para>
```
If you intend to use Docker, you need to run
`<command>`{=html}make`</command>`{=html} as superuser. If you are using
`<command>`{=html}sudo`</command>`{=html} to elevate your privileges,
you need to edit
`<filename>`{=html}katzenpost/docker/Makefile`</filename>`{=html} to
prepend `<command>`{=html}sudo`</command>`{=html} to each command
contained in it.
```{=html}
</para>
```
`</listitem>`{=html} `<listitem>`{=html}
```{=html}
<para>
```
If you have Podman installed on your system and you nonetheless want to
run Docker, you can override the default behavior by adding the argument
`<command>`{=html}docker=docker`</command>`{=html} to the command as in
the following:
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}make run
docker=docker`</command>`{=html}
```{=html}
</programlisting>
```
```{=html}
</para>
```
`</listitem>`{=html}
```{=html}
</itemizedlist>
```
```{=html}
</note>
```
```{=html}
<para>
```
The first time that you use `<command>`{=html}run`</command>`{=html} or
`<command>`{=html}start`</command>`{=html}, the docker image will be
downloaded, built, and installed. This takes several minutes.
```{=html}
</para>
```
```{=html}
<para>
```
Starting the network for the first time with
`<command>`{=html}run`</command>`{=html} lets you observe the
installation process as command output:
```{=html}
</para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}make run`</command>`{=html} \...
\<output\> \...
```{=html}
</programlisting>
```
```{=html}
<para>
```
Alternatively, you can install using
`<command>`{=html}start`</command>`{=html}, which returns you to a
command prompt. You can then use
`<command>`{=html}watch`</command>`{=html} to view the further progress
of the installation:
```{=html}
</para>
```
```{=html}
<para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}make start`</command>`{=html} \...
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}make watch`</command>`{=html} \...
\<output\> \...
```{=html}
</programlisting>
```
```{=html}
</para>
```
```{=html}
<para>
```
Once installation is complete, there is a further delay as the mix
servers vote and reach a consensus.
```{=html}
</para>
```
```{=html}
<para>
```
You can confirm that installation and configuration are complete by
issuing the `<command>`{=html}status`</command>`{=html} command from the
same or another terminal. When the network is ready for use,
`<command>`{=html}status`</command>`{=html} begins returning consensus
information similar to the following:
```{=html}
</para>
```
```{=html}
<para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}make status`</command>`{=html} \...
00:15:15.003 NOTI state: Consensus made for epoch 1851128 with 3/3
signatures: &{Epoch: 1851128 GenesisEpoch: 1851118 \...
```{=html}
</programlisting>
```
```{=html}
</para>
```
:::

::: {.section xml:id="test-mixnet"}
```{=html}
<title xml:id="test-mixnet.title">
```
Testing the mixnet
```{=html}
</title>
```
```{=html}
<para>
```
At this point, you should have a locally running mix network. You can
test whether it is working correctly by using
`<command>`{=html}ping`</command>`{=html}, which launches a packet into
the network and watches for a successful reply. Run the following
command:
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}make run-ping`</command>`{=html}
```{=html}
</programlisting>
```
```{=html}
</para>
```
```{=html}
<para>
```
If the network is functioning properly, the resulting output contains
lines similar to the following:
```{=html}
</para>
```
```{=html}
<programlisting>
```
19:29:53.541 INFO gateway1_client: sending loop decoy !19:29:54.108 INFO
gateway1_client: sending loop decoy 19:29:54.632 INFO gateway1_client:
sending loop decoy 19:29:55.160 INFO gateway1_client: sending loop decoy
!19:29:56.071 INFO gateway1_client: sending loop decoy !19:29:59.173
INFO gateway1_client: sending loop decoy !Success rate is 100.000000
percent 10/10)
```{=html}
</programlisting>
```
```{=html}
<para>
```
lf `<command>`{=html}ping`</command>`{=html} fails to receive a reply,
it eventually times out with an error message. If this happens, try the
command again.
```{=html}
</para>
```
```{=html}
<note>
```
```{=html}
<para>
```
If you attempt use
`<emphasis role="bold">`{=html}ping`</emphasis>`{=html} too quickly
after starting the mixnet, and consensus has not been reached, the
utility may crash with an error message or hang indefinitely. If this
happens, issue (if necessary) a
`<command>`{=html}Ctrl-C`</command>`{=html} key sequence to abort, check
the consensus status with the
`<command>`{=html}status`</command>`{=html} command, and then retry
`<command>`{=html}ping`</command>`{=html}.
```{=html}
</para>
```
```{=html}
</note>
```
:::

::: {.section xml:id="shutdown-mixnet"}
```{=html}
<title xml:id="shutdown-mixnet.title">
```
Shutting down the mixnet
```{=html}
</title>
```
```{=html}
<para>
```
The mix network continues to run in the terminal where you started it
until you issue a `<command>`{=html}Ctrl-C`</command>`{=html} key
sequence, or until you issue the following command in another terminal:
```{=html}
</para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}make stop`</command>`{=html}
```{=html}
</programlisting>
```
```{=html}
<para>
```
When you stop the network, the binaries and data are left in place. This
allows for a quick restart.
```{=html}
</para>
```
:::

::: {.section xml:id="uninstall-mixnet"}
```{=html}
<title xml:id="uninstall-mixnet.title">
```
Uninstalling and cleaning up
```{=html}
</title>
```
```{=html}
<para>
```
Several command targets can be used to uninstall the Docker image and
restore your system to a clean state. The following examples demonstrate
the commands and their output.
```{=html}
</para>
```
```{=html}
<itemizedlist>
```
`<listitem>`{=html}
```{=html}
<para>
```
`<command>`{=html}
```{=html}
<?oxy_comment_start author="dwrob" timestamp="20240628T130504-0700" comment="*make clean* requires superuser privileges. That seems strange since I installed via podman without elevated privileges. Is this a bug?  The problems seems to be with cache and code repo files." ?>
```
clean-bin
```{=html}
<?oxy_comment_end ?>
```
`</command>`{=html}
```{=html}
</para>
```
```{=html}
<para>
```
To stop the network and delete the compiled binaries, run the following
command:
```{=html}
</para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}make clean-bin`</command>`{=html} \[
-e voting_mixnet \] && cd voting_mixnet &&
DOCKER_HOST=unix:///run/user/1000/podman/podman.sock docker-compose down
\--remove-orphans; rm -fv running.stamp Stopping voting_mixnet_auth3_1
\... done Stopping voting_mixnet_servicenode1_1 \... done Stopping
voting_mixnet_metrics_1 \... done Stopping voting_mixnet_mix3_1 \...
done Stopping voting_mixnet_auth2_1 \... done Stopping
voting_mixnet_mix2_1 \... done Stopping voting_mixnet_gateway1_1 \...
done Stopping voting_mixnet_auth1_1 \... done Stopping
voting_mixnet_mix1_1 \... done Removing voting_mixnet_auth3_1 \... done
Removing voting_mixnet_servicenode1_1 \... done Removing
voting_mixnet_metrics_1 \... done Removing voting_mixnet_mix3_1 \...
done Removing voting_mixnet_auth2_1 \... done Removing
voting_mixnet_mix2_1 \... done Removing voting_mixnet_gateway1_1 \...
done Removing voting_mixnet_auth1_1 \... done Removing
voting_mixnet_mix1_1 \... done removed \'running.stamp\' rm -vf
./voting_mixnet/\*.alpine removed \'./voting_mixnet/echo_server.alpine\'
removed \'./voting_mixnet/fetch.alpine\' removed
\'./voting_mixnet/memspool.alpine\' removed
\'./voting_mixnet/panda_server.alpine\' removed
\'./voting_mixnet/pigeonhole.alpine\' removed
\'./voting_mixnet/ping.alpine\' removed
\'./voting_mixnet/reunion_katzenpost_server.alpine\' removed
\'./voting_mixnet/server.alpine\' removed
\'./voting_mixnet/voting.alpine\'
```{=html}
</programlisting>
```
```{=html}
<para>
```
This command leaves in place the cryptographic keys, the state data, and
the logs.
```{=html}
</para>
```
`</listitem>`{=html} `<listitem>`{=html}
```{=html}
<para>
```
`<command>`{=html}
```{=html}
<?oxy_comment_start author="dwrob" timestamp="20240628T130750-0700" comment="I need more description of what this is removing.  Run/start still very quickly start the network after this clean operation." ?>
```
clean-local
```{=html}
<?oxy_comment_end ?>
```
`</command>`{=html}
```{=html}
</para>
```
```{=html}
<para>
```
To delete both compiled binaries and data, run the following command:
```{=html}
</para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}make clean-local`</command>`{=html}
\[ -e voting_mixnet \] && cd voting_mixnet &&
DOCKER_HOST=unix:///run/user/1000/podman/podman.sock docker-compose down
\--remove-orphans; rm -fv running.stamp Removing voting_mixnet_mix2_1
\... done Removing voting_mixnet_auth1_1 \... done Removing
voting_mixnet_auth2_1 \... done Removing voting_mixnet_gateway1_1 \...
done Removing voting_mixnet_mix1_1 \... done Removing
voting_mixnet_auth3_1 \... done Removing voting_mixnet_mix3_1 \... done
Removing voting_mixnet_servicenode1_1 \... done Removing
voting_mixnet_metrics_1 \... done removed \'running.stamp\' rm -vf
./voting_mixnet/\*.alpine removed \'./voting_mixnet/echo_server.alpine\'
removed \'./voting_mixnet/fetch.alpine\' removed
\'./voting_mixnet/memspool.alpine\' removed
\'./voting_mixnet/panda_server.alpine\' removed
\'./voting_mixnet/pigeonhole.alpine\' removed
\'./voting_mixnet/reunion_katzenpost_server.alpine\' removed
\'./voting_mixnet/server.alpine\' removed
\'./voting_mixnet/voting.alpine\' git clean -f -x voting_mixnet Removing
voting_mixnet/ git status . On branch main Your branch is up to date
with \'origin/main\'.
```{=html}
</programlisting>
```
`</listitem>`{=html} `<listitem>`{=html}
```{=html}
<para>
```
`<command>`{=html}
```{=html}
<?oxy_comment_start author="dwrob" timestamp="20240628T130820-0700" comment="Again, I need a fuller inventory. I see that a lot of repo code is removed, and the cache. We could be more descriptive. Also, as noted, there is something weird with permissions needed for this command.. It makes no sense that I can set the testnet up as a reegular user, but I need to be root to remove it" ?>
```
clean
```{=html}
<?oxy_comment_end ?>
```
`</command>`{=html}
```{=html}
</para>
```
```{=html}
<para>
```
To stop the the network and delete the binaries, the data, and the
go_deps image, run the following command as superuser:
```{=html}
</para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}sudo make clean`</command>`{=html}
```{=html}
</programlisting>
```
`</listitem>`{=html} `<listitem>`{=html}
```{=html}
<para>
```
`<command>`{=html}clean-local-dryrun`</command>`{=html}
```{=html}
</para>
```
```{=html}
<para>
```
```{=html}
</para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}make
clean-local-dryrun`</command>`{=html} git clean -n -x voting_mixnet
Would remove voting_mixnet/
```{=html}
</programlisting>
```
```{=html}
<para>
```
```{=html}
</para>
```
`</listitem>`{=html}
```{=html}
</itemizedlist>
```
```{=html}
<para>
```
```{=html}
</para>
```
```{=html}
<programlisting>
```
`<prompt>`{=html}\~/katzenpost/docker\$
`</prompt>`{=html}`<command>`{=html}make clean`</command>`{=html}
```{=html}
</programlisting>
```
```{=html}
<para>
```
For a preview of the components that
`<command>`{=html}clean-local`</command>`{=html} would remove, without
actually deleting anything, running
`<command>`{=html}clean-local-dryrun`</command>`{=html} generates output
as follows:
```{=html}
</para>
```
:::
:::

::: {.section xml:id="topology"}
```{=html}
<title xml:id="topology.title">
```
Network components and topology
```{=html}
</title>
```
```{=html}
<para>
```
There needs to be an interpretation of this diagram. including the ways
that the testnet differs from production network.
```{=html}
</para>
```
```{=html}
<figure>
```
```{=html}
<title>
```
Test network topology
```{=html}
</title>
```
```{=html}
<mediaobject>
```
`<imageobject>`{=html}
`<imagedata fileref="../Diagrams/katzenpost-docker-net-4.png" scale="75">`{=html}`</imagedata>`{=html}
`</imageobject>`{=html}
```{=html}
</mediaobject>
```
```{=html}
</figure>
```
```{=html}
<para>
```
Discuss how to view these components, where their configuration files
are, etc.
```{=html}
</para>
```
```{=html}
<table frame="all">
```
```{=html}
<title>
```
```{=html}
<?oxy_comment_start author="dwrob" timestamp="20240617T174147-0700" comment="I will define/describe each of these component types in a separate section, because they are general and not specific to the testnet. These host types will be linked to that.

[Update: Deferring discussion of Spool.DB and User.DB until documentations for indivdual components; not relevant for Docker image. These DBs live on the Gateway host.]

[Update: adding gateway host.]" ?>
```
Network hosts
```{=html}
<?oxy_comment_end ?>
```
```{=html}
</title>
```
`<tgroup cols="5">`{=html}
`<colspec colname="c1" colnum="1" colwidth="1*">`{=html}`</colspec>`{=html}
`<colspec colname="c2" colnum="2" colwidth="1*">`{=html}`</colspec>`{=html}
`<colspec colname="c3" colnum="3" colwidth="1*">`{=html}`</colspec>`{=html}
`<colspec colname="c4" colnum="4" colwidth="1*">`{=html}`</colspec>`{=html}
`<colspec colname="newCol8" colnum="5" colwidth="1*">`{=html}`</colspec>`{=html}
```{=html}
<thead>
```
`<row>`{=html} `<entry>`{=html}Host type`</entry>`{=html}
`<entry>`{=html}Identifier`</entry>`{=html}
`<entry>`{=html}IP`</entry>`{=html}
`<entry>`{=html}Port`</entry>`{=html}
`<entry>`{=html}Panda`</entry>`{=html} `</row>`{=html}
```{=html}
</thead>
```
```{=html}
<tbody>
```
`<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Directory authority
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}auth1`</entry>`{=html}
`<entry>`{=html}
```{=html}
<para>
```
127.0.0.1
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
30001
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Directory authority
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
auth2
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
127.0.0.1
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
30002
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Directory authority
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
auth3
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
127.0.0.1
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
30003
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}Gateway
node`</entry>`{=html} `<entry>`{=html}gateway1`</entry>`{=html}
`<entry>`{=html}
```{=html}
<para>
```
127.0.0.1
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}30004`</entry>`{=html}
`<entry>`{=html}
```{=html}
<para>
```
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Service node
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
servicenode1
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
127.0.0.1
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
30006
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
✓
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Mix node
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
mix1
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
127.0.0.1
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
30008
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Mix node
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
mix2
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
127.0.0.1
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
30010
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html} `<row>`{=html} `<entry>`{=html}
```{=html}
<para>
```
Mix node
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
mix3
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
127.0.0.1
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
30012
```{=html}
</para>
```
`</entry>`{=html} `<entry>`{=html}
```{=html}
<para>
```
```{=html}
</para>
```
`</entry>`{=html} `</row>`{=html}
```{=html}
</tbody>
```
`</tgroup>`{=html}
```{=html}
</table>
```
:::

`</chapter>`{=html}
