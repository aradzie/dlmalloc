# dlmalloc

This is a cleaned-up version of the Doug Lea's `dlmalloc`. The original source
code is written in a strange dialect of C. It is a single huge source file
infested with macros. All of this makes the source code much less readable and
understandable. To simplify it I split it into multiple modules and rewrote
macros to inline functions. I did not care about compatibility, I threw out
some of the old stuff, simplified other, so this is not a drop-in replacement
for the original project and should not be used in production. It's just a
tutorial in implementing memory allocators.
