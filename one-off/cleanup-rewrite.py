#!/usr/bin/env python
# Detects init functions with just reassembly functionality and adds a
# corresponding cleanup function for it.

# 1. Load file containing lines with: path/to/file.c:foo_init
# 2. Find function, extract it.
# 3. Append cleanup func.
# 4. Find register_init_routine call and append cleanup call.
#
# Detect init function:
#   static void foo_init(void) {
#       // one or more lines. Non-empty lines are processed as shown below.
#       // Note that functions may split over multiple lines and that indent
#       // might differ.
#   }
#
# Keep comments in output:
#       /* optional comments,
#        * possibly multiline */
#
# Keep reassembly, remember R_NAME:
#       reassembly_table_init(&R_NAME, &functions);
#
# Strip hash table destroy and if conditions, remember name:
#       if (HT_NAME) g_hash_table_destroy(HT_NAME);
#       if (HT_NAME != NULL) { /* ... */ }
#       if (HT_NAME) {
#           g_hash_table_destroy(HT_NAME);
#           HT_NAME = NULL; // ignore this as well if any
#       }
#
# Keep hash table init:
#       HT_NAME = g_hash_table_new_full(...);
#       HT_NAME = g_hash_table_new(...);
#
# Keep, but mark as TODO (or ignore for now?):
#       varname = 0;
#       varname = NULL;
#
#
# After init function:
# Output g_hash_table_destroy for each HT_NAME
# Output reassembly_table_destroy for each R_NAME.

import sys, re, logging
_logger = logging.getLogger(__name__)

# Set to True to allow more code to be modified.
# Unknown lines will be suffixed with a " // FIXME" comment.
AUDIT = False

# For quick sanity checking (funcName, is_prototype)
RE_FUNCTION_HEADER = re.compile(
        r'''
        (?:static \s+) ?void    \s+
        (?P<funcName>\w+)       \s*
        \(\s*void\s*\)              # "(void)"
        (?P<is_prototype>\s*;[^\n]*\n)? # Non-empty if this is the prototype,
                                    # contains the remaining line as well.
        ''', re.X)
# TODO: maybe detect prototypes?
# Matches init/cleanup function signature (funcName, body)
RE_FUNCTION = re.compile(
        r'''
        ^(?:static \s+ )?void   \s+ # "static void" - prefix
        (?P<funcName>\w+)       \s* # "foo_init" - function name
        \([^)]*\) \s*   \{          # "(void) {" - function params
        (?P<body>
            [^\n]+                  # everything on one line { ... }
            |
            (?:                     # Handle multiple lines
                \n[^}][^\n]+        # heh, forget '\n' and you run into a loop...
                |
                \n                  # Handle empty lines
            )+
        )               \}[^\n]*\n  # "} /* foo_init */" - end of function
        ''', re.M | re.X)
RE_IF = re.compile(
        r'''
        if\s*\(\s*                  # "if ("
            (?P<varName>[.\w]+)\s*  # "HT_NAME "
            (?:!=\s* (?:NULL|0))?   # "!= NULL
        \)                          # ")"
        ''', re.X)
# Matches reassembly lines
RE_REASS = re.compile('reassembly_table_init\s*\(\s*(?P<name>[^\s,]+)')
# Matches "g_hash_table_destroy(HT_NAME)"
RE_HT_DESTROY = re.compile(r'''
        (?:
            g_hash_table_foreach_remove|
            g_hash_table_destroy
        )\s*\(\s*                       # "g_hash_table_destroy("
        (?P<varName>[.\w]+)\s*          # "struct.ht_name"
        [^)]*                           # params for g_hash_table_foreach_remove
        \)                              # ")"
        ''', re.X)
RE_ASSIGNMENT = re.compile(r'(?P<varName>[.\w]+)\s*=\s*(?P<value>[^;]*)')

class Function(object):
    def __init__(self, name, body, func_match):
        self.name = name
        self.body = body
        self.func_match = func_match
        self.lines_keep = ''
        self.reassemble_names = []
        self.ht_names = []
        self.unknown_lines = ''

    def detect_comment(self, text, multiline_comment):
        if multiline_comment:
            multiline_comment = not text.endswith('*/')
            # Assume that there is no code after the end marker
            return True, multiline_comment
        else:
            multiline_comment = text.startswith('/*')
            if multiline_comment:
                multiline_comment = not text.endswith('*/')
                return True, multiline_comment
            if text.startswith('//'):
                return True, False
        # Not a comment, not a multi-line comment
        return False, False

    def parse(self):
        """Call it once to parse the given function body."""
        multiline_comment = False
        # Find all functional lines
        self._lines_iter = iter(self.body.splitlines(True))
        for line in self._lines_iter:
            # Track whether the line was understood or not
            # None = needs check, False = invalid, True = handled
            handled = None

            # Ignore empty lines.
            text = line.strip()
            if not text:
                continue

            # Keep comments, but ignore them for parsing
            is_comment, multiline_comment = self.detect_comment(text,
                    multiline_comment)
            if is_comment:
                # Uncomment to keep comments (might also have to do this for
                # RE_ASSIGNMENT below).
                #self.lines_keep += line
                handled = True

            # detect reassembly function
            if handled is None:
                reass_match = RE_REASS.match(text)
                if reass_match:
                    handled = self.handle_reasembly(reass_match, line)

            if handled is None:
                # Find if/hashtable stuff
                if_match = RE_IF.match(text)
                if if_match:
                    _logger.debug('Found if in: %s', text)
                    handled = self.handle_if(if_match, line)

            if handled is None:
                # Find assignments such as hash table things
                assignment_match = RE_ASSIGNMENT.match(text)
                if assignment_match:
                    _logger.debug('Found assignment in: %s', text)
                    varName = assignment_match.group('varName')
                    # Hash table creation
                    line, text = self._read_stmt(line)
                    if 'g_hash_table_new' in text:
                        _logger.debug('Found hash table in: %s', text)
                        if varName not in self.ht_names:
                            _logger.warn('HT %s was not destructed', varName)
                            #self.ht_names.append(varName)
                        self.lines_keep += line
                        handled = True
                    else:
                        # Not sure if init or destruct, mark it to be sure.
                        self.lines_keep += line.replace('\n', ' // FIXME\n')
                        handled = True

            if not handled:
                if AUDIT:
                    self.lines_keep += line.replace('\n', ' // FIXME\n')
                else:
                    self.unknown_lines += line

        if self.unknown_lines:
            _logger.error('Unknown lines in %s:\n%s',
                self.name, self.unknown_lines)
            return False
        _logger.info('Found function %s', self.name)
        _logger.info('Keep function  %s:\n%s', self.name, self.lines_keep)
        return True

    def _read_stmt(self, line='', terminator=';'):
        """
        Reads lines until a full statement is ready.
        :param line: current buffer that needs to be finished
        """
        text = line.strip()
        ml_comment = False
        while terminator not in text:
            line2 = next(self._lines_iter)
            text2 = line2.strip()
            is_comment, ml_comment = self.detect_comment(text2, ml_comment)
            line += line2
            if not is_comment:
                text += '\n' + text2
        return line, text

    def handle_reasembly(self, reass_match, line):
        self.reassemble_names.append(reass_match.group('name'))
        # Handle following lines and jump to next detection.
        line, _ = self._read_stmt(line)
        self.lines_keep += line
        return True

    def handle_if(self, if_match, line):
        text = line.strip()
        # Expected more?
        if '{' in text:
            # Look for if (...) { ... }
            line, text = self._read_stmt(line, '}')
        else:
            # Look for if (...) ...;
            line, text = self._read_stmt(line, ';')
            # Handle newline between "if (...)" and "{"
            if '{' in text:
                line, text = self._read_stmt(line, '}')

        has_else = re.search(r'\}\s*else\b', text)

        # Get rid of if condition and brackets
        if '{' in text:
            text = text.split('{', 1)[1].split('}')[0]
        else:
            text = text.split(')', 1)[1]

        # The variable that was tested for destruction
        varName = if_match.group('varName')
        # For each statement in the if-body, check validity
        for stmt in text.split(';'):
            stmt = stmt.strip()
            if not stmt:
                continue
            ht_destroy_match = RE_HT_DESTROY.match(stmt)
            if ht_destroy_match:
                if ht_destroy_match.group('varName') != varName:
                    _logger.error('cond %s != destroy %s' %
                            (varName, ht_destroy_match.group('varName')))
                    self.unknown_lines += line
                    return True
                # Remember name for later destruction
                self.ht_names.append(varName)
                _logger.debug('Skipping line for ht destroy %s', varName)
                continue
            assignment_match = RE_ASSIGNMENT.match(stmt)
            if assignment_match:
                if assignment_match.group('varName') == varName and \
                    assignment_match.group('value') in ('NULL', '0') and \
                    self._is_ht_name(varName):
                    # Ignore clearing variable for hash table
                    continue
            _logger.warn('Unhandled if stmt: %s', stmt)
            self.unknown_lines += line
            return True

        # If an else is present, continue searching for more
        if has_else:
            line, text = self._read_stmt('', '}')
            if 'g_hash_table_new' in text:
                line = line.split('}', 1)[0]
                indent = self.get_indent()
                line = ''.join([l.replace(indent, '', 1)
                        for l in line.splitlines(True)])
                text = line
                _logger.debug('Found hash table in else: %s', text)
                if varName not in self.ht_names:
                    _logger.warn('HT %s was not destructed', varName)
                    #self.ht_names.append(varName)
                self.lines_keep += line
            else:
                # Hmm... no idea what this is.
                self.unknown_lines += line

        return True

    def _is_ht_name(self, varName):
        patt_ht_new = r'^\s*' + re.escape(varName) + r'\s*=\s*g_hash_table_new'
        return re.search(patt_ht_new, self.body, re.M) is not None

    def get_indent(self):
        indent_match = re.search(r'^\n*([ \t]+)', self.body, re.M)
        if not indent_match:
            _logger.error('Could not detect indent level for %s!', funcName)
            # XXX can this actually happen?
            return ''
        return indent_match.group(1)

    def _make_function(self, funcName, body, keep_trailer=False):
        # "static void" funcName "(void) {" body "}\n"
        begin,   end   = self.func_match.span()
        f_begin, f_end = self.func_match.span('funcName')
        b_begin, b_end = self.func_match.span('body')
        context = self.func_match.string
        code = ''
        code += context[begin:f_begin] + funcName   # "static void" funcName
        code += context[f_end:b_begin] + '\n'       # "(void) {\n"
        code += body
        # Strip comments in "}\n" unless requested otherwise (for init)
        code += context[b_end:] if keep_trailer else '}\n'
        return code

    def make_cleanup_function(self, cleanupFuncName):
        body = self._make_cleanup_function_body()
        if not body:
            return
        code = self._make_function(cleanupFuncName, body)
        _logger.debug('Emitting cleanup routine %s:\n%s', cleanupFuncName, code)
        return code

    def _make_cleanup_function_body(self):
        body = ''
        indent = self.get_indent()
        for name in self.reassemble_names:
            body += '%sreassembly_table_destroy(%s);\n' % (indent, name)
        for name in self.ht_names:
            body += '%sg_hash_table_destroy(%s);\n' % (indent, name)
        return body

    def make_init_function(self):
        """Generates the stripped init routine."""
        code = self._make_function(self.name, self.lines_keep, keep_trailer=True)
        assert code
        _logger.debug('Emitting init routine %s:\n%s', self.name, code)
        # As the block is replaced, remember the context
        begin, end = self.func_match.span()
        context = self.func_match.string
        return context[0:begin] + code + context[end:]


class Source(object):
    def __init__(self, filename):
        self.filename = filename
        self.blocks = []
        # map from function names to a tuple
        # (blockIndex:int, func:Function, func_match:re.Match)
        self.functions = {}
        # map from prototype function name to a tuple
        # (blockIndex:int, fn:re.Match)
        self.prototypes = {}

    def parse_func(self, block, blockIndex):
        """
        Parses the code block. The blockIndex parameter is used for indexing the
        functions.
        """
        # Quick sanity check (multiple names may show up as it matches
        # prototypes and other functions with any number of parameters).
        funcNames_guessed = []
        for fn in RE_FUNCTION_HEADER.finditer(block):
            funcName = fn.group('funcName')
            funcNames_guessed.append(funcName)
            if fn.group('is_prototype'):
                if funcName in self.prototypes:
                    _logger.error('Prototype %s is already known, overwriting!',
                            funcName)
                self.prototypes[funcName] = (blockIndex, fn)

        if not funcNames_guessed:
            return
        _logger.debug('Found functions %s', ', '.join(funcNames_guessed))

        # Try to match the init function
        func_match = RE_FUNCTION.search(block)
        if not func_match:
            _logger.info('No function body detected for %s',
                    ', '.join(funcNames_guessed))
            return

        # Try to parse everything from the function body
        funcName = func_match.group('funcName')
        body = func_match.group('body')
        func = Function(funcName, body, func_match)
        if funcName in self.functions:
            _logger.error('Function %s is already known, overwriting!', funcName)
        _logger.debug('Saving function %s', funcName)
        self.functions[funcName] = (blockIndex, func, func_match)

    def parse_block(self, block):
        self.parse_func(block, len(self.blocks))
        self.blocks.append(block)

    def parse(self):
        block = ''
        # Pass 1: read file contents and extract functions
        with open(self.filename) as f:
            for line in f:
                block += line
                # Assume end of line / begin of block
                # use heuristics to match:
                # static void reset_dissector(void) { ...; }
                if line.startswith('}') or (
                        line.startswith('static void') and
                        '(void)' in line and
                        line.endswith('}\n')
                    ):
                    self.parse_block(block)
                    block = ''
                    continue
            # Remainder
            if block:
                self.parse_block(block)
                block = ''

        # Pass 2: find register_init_routine, append cleanup call and append
        # cleanup function.
        for blockIndex, block in enumerate(self.blocks):
            if self.try_init_fix(block, blockIndex):
                # Ok, cleanup routine is fixed.
                return True
        return False

    def make_cleanup_name(self, funcName):
        newName = funcName.replace('init', 'cleanup')
        newName = newName.replace('setup', 'cleanup')
        if funcName == newName:
            _logger.error('Cannot create unique cleanup function name %s',
                funcName)
        return newName

    def try_init_fix(self, block, blockIndex):
        # Matches " register_init_routine (&foo_init);"
        caller_match = re.search(
                r'''
                ^(?P<line>
                    (?:[ \t]*)register_init_routine\s*
                    \(\s* &? \s*(?P<name>\w+)\s* \);
                )[^\n]*\n
                ''', block, re.M | re.X)
        if not caller_match:
            # Sanity check
            if re.search(r'register_init_routine\s*\(', block):
                _logger.error('Could not detect register_init_routine properly!')
            return False # Continue searching

        # Locate init function and generate matching cleanup function
        funcName = caller_match.group('name')
        cleanupFuncName = self.make_cleanup_name(funcName)
        if not self.fix_cleanup_function(funcName, cleanupFuncName):
            return

        # Yields " register_cleanup_routine (&foo_cleanup);"
        extra_line = caller_match.group('line') \
            .replace('register_init_routine', 'register_cleanup_routine') \
            .replace(funcName, cleanupFuncName)
        extra_line += '\n'
        begin, end = caller_match.span()
        self.blocks[blockIndex] = block[0:end] + extra_line + block[end:]
        return True # Done searching

    def fix_cleanup_function(self, funcName, cleanupFuncName):
        if not funcName in self.functions:
            _logger.error('Init routine %s not found!', funcName)
            return False

        if cleanupFuncName in self.functions:
            _logger.error('Cleanup routine %s already exists!', cleanupFuncName)
            return False

        blockIndex, func, func_match = self.functions[funcName]
        if not func.parse():
            return False

        initCode = func.make_init_function()
        cleanupCode = func.make_cleanup_function(cleanupFuncName)
        if not cleanupCode:
            return False # Empty function

        # Add prototypes if necessary
        if funcName in self.prototypes:
            self.fix_cleanup_proto(funcName, cleanupFuncName)

        self.blocks[blockIndex] = initCode
        self.blocks[blockIndex] += '\n' + cleanupCode
        return True

    def fix_cleanup_proto(self, funcName, cleanupFuncName):
        protoBlockIndex, fn = self.prototypes[funcName]
        begin,   end   = fn.span()
        f_begin, f_end = fn.span('funcName')
        context = fn.string
        block = context[0:end]          # up until "proto_init(void);\n"
        block += context[begin:f_begin] # "static void "
        block += cleanupFuncName        # "proto_cleanup"
        block += '(void);\n'            # "(void);\n"
        block += context[end:]          # remaining code
        self.blocks[protoBlockIndex] = block

    def __str__(self):
        return ''.join(self.blocks)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
        format='%(name)s:%(levelname)s: %(message)s')
    # Color!
    for _level, _color in {
        'ERROR':    31,
        'WARNING':  33,
        'INFO':     37,
        'DEBUG':    34,
    }.items():
        logging.addLevelName(getattr(logging, _level),
            '\033[%d;1m%s\033[m' % (_color, _level))

    write_file = lambda f, data: sys.stdout.write(data)

    args = sys.argv[1:]
    if not args:
        _logger.error('Usage: cleanup-rewrite.py [-w] files..')
        sys.exit(1)

    if args[0] == '-w':
        args = args[1:]
        _logger.info('Will write new files')
        write_file = lambda f, data: open(f, 'w').write(data)

    ok = None
    for filename in args:
        # Support aliasing files such as /dev/stdin:/dev/stdout
        if ':' in filename:
            filename_in, filename = filename.split(':', 1)
        else:
            filename_in = filename

        # Linux-only hack: alias - as stdin or stdout
        if filename_in == '-':
            filename_in = '/dev/stdin'
        if filename == '-':
            filename = '/dev/stdout'

        src = Source(filename_in)
        if src.parse():
            if ok is None:
                ok = True
            write_file(filename, str(src))
        else:
            ok = False

    sys.exit(0 if ok else 1)
