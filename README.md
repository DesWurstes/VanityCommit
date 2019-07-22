# VanityCommit

Ultra-fast Git commit SHA-1 hash brute forcing tool.

![An example of commit bruteforcing (Although this commit was made before this tool's source code was published.)](https://user-images.githubusercontent.com/23437045/41810142-e86d3eae-7701-11e8-8cda-9b95fef4ff19.png)

From the developers of [Vanitygen Cash](https://github.com/cashaddress/vanitygen-cash), the Bitcoin Cash address prefix tool.

## What does it do?

Did you know that it's possible to set the prefix of Git commits? With this tool, you can decide the prefix of the commit hashes. It can be of any length. GiHub usually shows the first seven characters, and this tool finds a solution under two minutes on my computer.

## Usage

1) Commit as usual
2) `cd` into repository
3) Run VanityCommit as `./VanityCommit 01abc`

Syntax:

```
./VanityCommit <hex prefix> [<timezone +0100>]
```

## Download

Go to [releases](/releases)

## Building

Linux & Mac:

```
gcc-8 main.c -lpthread -Ofast -march=native -o VanityCommit
```

Windows (Visual Studio Developer Tools): // Coming SOON

```
cl main.c -o VanityCommit
```

## Behind the scenes

Starting from the commit time, it assigns each thread an `author` timestamp. They each decrease `committer` timestamps until they find a solution or reach the delta constant.

## Detecting it

The `author` and the `committer` timestamps are equal, unless a commit was amended.

Use `git log --pretty=fuller -1 <hash>` or `git cat-file -p <hash>`, then compare the timestamps.

## Alternatives

- [GitBrute](https://github.com/bradfitz/gitbrute): Golang is a great language for parallelism, although the trial generator is not efficient and some parts could be optimized more (e.g. regex).

- [vanity-commit](https://github.com/clickyotomy/vanity-commit): Python may not be the best choice for speed. On the contrary, the code is readable and easy to understand. The name is just a coincidence.

- [git-vanity](https://github.com/tochev/git-vanity): Using OpenCL for bruteforcing is a great idea, but it doesn't work for me; probably due to small bugs.

- [git-vanity-sha](https://github.com/mattbaker/git-vanity-sha): Very polite, asks you for amendment confirmation, and pretty fast. Works similar to Vanity Commit. Unfortunately, it gives up when it reaches the constant.

- [lhc](https://github.com/stuartpb/lhc): Written in early-2013-era Node.js - this implementation is unique in that it inserts from a word list into the content of the commit message to find the collision.

- [the "lulz header"](http://lists-archives.com/git/756392-choosing-the-sha1-prefix-of-your-commits.html): a patch from 2011 that adds this functionality to `git-commit` itself

## TODO

- [ ] Search for multiple prefixes
- [ ] Option to keep timestamps synchronized
- [ ] Extend max commit length
- [ ] Keep commiter & author names
- [ ] Add bruteforcing by timezone
- [ ] OpenCL for extremely vain hashes
