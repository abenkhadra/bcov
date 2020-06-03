
## bcov

A tool for efficient binary-level coverage analysis. `bcov` statically
instruments x86-64 ELF binaries without compiler support. It features probe
pruning, precise CFG analyses, and sophisticated instrumentation techniques.

## Resources

  - Full details are available in our upcoming ESEC/FSE'20 [paper][link-preprint].
  - This [blog post][link-post] elaborates on the rationale behind our function
  model and the availability of function definitions in stripped binaries.

## Software prerequisites

The following software must be available:
   - [capstone][link-capstone] branch `next` commit #c3b4ce1901
   - [unicorn][link-unicorn]  branch `master` commit #536c4e77c4

Later versions of both frameworks should work in principle but have not been
tested yet.

## Research replicability

Please checkout the accompanying [artifacts][link-artifacts].

## Sample usage

The following command can be issued to patch a binary,

```shell script
bcov -m patch -p any -v 5 -i perl -o perl.any
```

The operation mode can be set either to `patch` for instrumentation or `report`
for coverage reporting. The instrumentation policy can be set to `any`, which
refers to the any-node policy, or `all` which refers to the leaf-node policy.

Coverage data can be dumped by injecting `libbcov-rt.so` using the `LD_PRELOAD`
mechanism. For example, you can try the sample binary `perl.any` which can be
found in the artifacts repository,

```shell script
export BCOV_OPTIONS="coverage_dir=$PWD"   # sets the directory for dumping coverage data
export LD_PRELOAD="[full-path-to-bcov-rt]/libbcov-rt.so"
./perl.any -e 'print "Hello, bcov\n"'
```

This will produce a dump file that has the suffix '.bcov' in your current
directory . This file can be supplied to `bcov` for coverage reporting,

```shell script
bcov -m report -p any -i ./perl -d perl.any.1588260679.1816.bcov > report.out
```

Currently, `bcov` still can not persist analysis results between binary
patching and coverage reporting. Therefore, the original binary has to be
re-analyzed. Coverage will be reported for each basic block in the file
`report.out`. The data in each line lists:
 - BB address
 - BB instruction count
 - is covered
 - is fallthrough (i.e., does not terminate with a branch)

Also, a coverage summary is reported for each function.


## Citing

For citation in an academic work please use:

    @inproceedings{BenKhadra:FSE2020,
    address = {Sacramento, CA, USA},
    author = {{Ben Khadra}, M. Ammar and Stoffel, Dominik and Kunz, Wolfgang},
    booktitle = {ACM Joint European Software Engineering Conference and Symposium on the Foundations of Software Engineering - ESEC/FSE'20 (accepted)},
    publisher = {ACM Press},
    title = {{Efficient Binary-Level Coverage Analysis}},
    year = {2020}
    }

## License

This software is distributed under the MIT license. See `LICENSE.txt` for details.

 [link-capstone]: https://github.com/aquynh/capstone
 [link-unicorn]: https://github.com/unicorn-engine/unicorn
 [link-preprint]: https://arxiv.org/abs/2004.14191
 [link-artifacts]: https://github.com/abenkhadra/bcov-artifacts
 [link-post]: https://blog.formallyapplied.com/2020/05/function-identification/

