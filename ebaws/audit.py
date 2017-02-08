#!/usr/bin/env python
# -*- coding: utf-8 -*-
from threading import Lock as Lock
import json
import collections
import logging
import time
import util
import os
import traceback
import types


logger = logging.getLogger(__name__)


class AuditManager(object):
    """
    Handles installer actions auditing
    """
    def __init__(self, audit_file=None, append=False, to_root=False, disabled=False, auto_flush=False,
                 *args, **kwargs):
        self.append = append
        self.audit_file = audit_file
        self.audit_records_buffered = []
        self.audit_lock = Lock()
        self.audit_ctr = 0
        self.to_root = to_root
        self.disabled = disabled
        self.auto_flush = auto_flush

    def _log(self, log):
        """
        Appends audit log to the buffer. Lock protected.
        :param log:
        :return:
        """
        with self.audit_lock:
            if self.disabled:
                return

            self.audit_records_buffered.append(log)
        self._autoflush()

    def _filecheck(self):
        """
        Checks audit file, creates a new one if needed.
        :return:
        """
        if self.audit_file is None:
            if self.to_root:
                self.audit_file = os.path.join('/root', 'eb-audit.json')
                try:
                    logger.debug('Trying audit file %s' % self.audit_file)
                    return self._open_audit_file()
                except (IOError, OSError):
                    pass

            self.audit_file = os.path.join(os.getcwd(), 'eb-audit.json')
            try:
                logger.debug('Trying audit file %s' % self.audit_file)
                return self._open_audit_file()
            except (IOError, OSError):
                pass

            self.audit_file = os.path.join('/tmp', 'eb-audit.json')
            try:
                logger.debug('Trying audit file %s' % self.audit_file)
                return self._open_audit_file()
            except (IOError, OSError):
                pass

            self.audit_file = os.path.join('/tmp', 'eb-audit-%d.json' % int(time.time()))

        logger.debug('Audit file %s' % self.audit_file)
        return self._open_audit_file()

    def _open_audit_file(self):
        """
        Opens the audit file
        :return:
        """
        if self.audit_ctr == 0 and not self.append:
            fh, backup = util.safe_create_with_backup(self.audit_file, 'a', 0o600)
            self.audit_ctr += 1
            return fh

        self.audit_ctr += 1
        return util.safe_open_append(self.audit_file, 0o600)

    def _autoflush(self):
        if self.auto_flush:
            self.flush()

    def _newlog(self, evt=None):
        log = collections.OrderedDict()
        log['time'] = time.time()
        if evt is not None:
            log['evt'] = evt
        return log

    def _valueize_key(self, key):
        """
        Allows only string keys, numerical keys
        :param key:
        :return:
        """
        if isinstance(key, types.StringTypes):
            return key
        if isinstance(key, (types.BooleanType, types.IntType, types.LongType, types.FloatType)):
            return key
        return '%s' % key

    def _valueize(self, value):
        """
        Normalizes value to JSON serializable element.
        Tries to serialize value to JSON, if it fails, it is converted to the string.
        :param value:
        :return:
        """
        if isinstance(value, types.StringTypes):
            return value
        if isinstance(value, (types.BooleanType, types.IntType, types.LongType, types.FloatType)):
            return value

        # Try JSON serialize
        try:
            json.dumps(value)
            return value
        except TypeError:
            pass

        # Tuple - convert to list
        if isinstance(value, types.TupleType):
            value = list(value)

        # Special support for lists and dictionaries
        # Preserve type, encode sub-values
        if isinstance(value, types.ListType):
            return [self._valueize(x) for x in value]

        elif isinstance(value, types.DictionaryType):
            return {self._valueize_key(key): self._valueize(value) for (key, value) in value}

        else:
            return '%s' % value

    def _args_to_log(self, log, *args):
        """
        Transforms arguments to the log
        :param log:
        :param args:
        :return:
        """
        if args is None:
            return

        for idx, arg in enumerate(args):
            log['arg%d' % idx] = self._valueize(arg)

    def _kwargs_to_log(self, log, **kwargs):
        """
        Translates kwargs to the log entries
        :param log:
        :param kwargs:
        :return:
        """
        if kwargs is None:
            return

        for key, value in kwargs.iteritems():
            log[self._valueize_key(key)] = self._valueize(value)

    def flush(self):
        """
        Flushes audit logs to the JSON append only file.
        Routine protected by the lock (no new audit record can be inserted while holding the lock)
        :return:
        """
        with self.audit_lock:
            if self.disabled:
                return

            try:
                if len(self.audit_records_buffered) == 0:
                    return

                with self._filecheck() as fa:
                    for x in self.audit_records_buffered:
                        fa.write(json.dumps(x) + "\n")
                self.audit_records_buffered = []
            except Exception as e:
                logger.debug(traceback.format_exc())
                logger.error('Exception in audit log dump %s' % e)

    def audit_exec(self, cmd, cwd=None, retcode=None, stdout=None, stderr=None, exception=None, exctrace=None, *args, **kwargs):
        """
        Audits command execution
        :param cmd: command
        :param cwd: current working directory
        :param retcode: return code
        :param stdout: standard output
        :param stderr: standard error output
        :param exception: exception
        :param exctrace: exception traceback
        :return:
        """
        log = self._newlog('exec')
        log['cmd'] = self._valueize(cmd)
        if cwd is not None:
            log['cwd'] = self._valueize(cwd)
        if retcode is not None:
            log['retcode'] = self._valueize(retcode)
        if stdout is not None:
            log['stdout'] = self._valueize(stdout)
        if stderr is not None:
            log['stderr'] = self._valueize(stderr)
        if exception is not None:
            log['exception'] = self._valueize(exception)
        if exctrace is not None:
            log['exctrace'] = self._valueize(exctrace)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_copy(self, src, dst, *args, **kwargs):
        """
        Audits file copy
        :param src:
        :param dst:
        :return:
        """
        log = self._newlog('copy')
        log['src'] = self._valueize(src)
        log['dst'] = self._valueize(dst)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_move(self, src, dst, *args, **kwargs):
        """
        Audits file move
        :param src:
        :param dst:
        :return:
        """
        log = self._newlog('move')
        log['src'] = self._valueize(src)
        log['dst'] = self._valueize(dst)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_file_create(self, fname, data=None, chmod=None, *args, **kwargs):
        """
        Audits a file creation
        :param fname:
        :param data:
        :param chmod:
        :return:
        """
        log = self._newlog('fnew')
        log['name'] = fname
        if chmod is not None:
            log['chmod'] = self._valueize(data)
        if data is not None:
            log['data'] = self._valueize(data)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_remove(self, fname, *args, **kwargs):
        self.audit_delete(fname, *args, **kwargs)

    def audit_delete(self, fname, *args, **kwargs):
        """
        Audits file deletion
        :param fname:
        :return:
        """
        log = self._newlog('fdel')
        log['name'] = self._valueize(fname)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_file_read(self, fname, data=None, *args, **kwargs):
        """
        File read
        :param fname:
        :param data:
        :return:
        """
        log = self._newlog('fread')
        log['name'] = self._valueize(fname)
        if data is not None:
            log['data'] = self._valueize(data)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_file_write(self, fname, data=None, chmod=None, *args, **kwargs):
        """
        File write
        :param fname:
        :param data:
        :param chmod:
        :return:
        """
        log = self._newlog('fwrite')
        log['name'] = self._valueize(fname)
        if chmod is not None:
            log['chmod'] = self._valueize(data)
        if data is not None:
            log['data'] = self._valueize(data)

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_download(self, url, retcode=None, *args, **kwargs):
        """
        Download action
        :param url:
        :return:
        """
        log = self._newlog('download')
        log['url'] = self._valueize(url)
        if retcode is not None:
            log['retcode'] = self._valueize(retcode)

        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_request(self, url=None, data=None, desc=None, *args, **kwargs):
        """
        API request (e.g., JSON)
        :param url:
        :param data:
        :return:
        """
        log = self._newlog('request')
        if url is not None:
            log['url'] = self._valueize(url)
        if desc is not None:
            log['desc'] = self._valueize(desc)
        if data is not None:
            log['data'] = self._valueize(data)

        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_exception(self, exception=None, exctrace=None, *args, **kwargs):
        """
        Audits exception
        :param exception:
        :param exctrace:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('exception')
        if exception is not None:
            log['exception'] = self._valueize(exception)
        if exctrace is not None:
            log['exctrace'] = self._valueize(exctrace)
        else:
            try:
                log['exctrace'] = self._valueize(traceback.format_exc())
            except:
                pass

        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_error(self, *args, **kwargs):
        """
        Error auditing
        :param evt:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('error')
        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_print(self, *args, **kwargs):
        """
        Command line auditing - printing
        :param lines:
        :param sensitive:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('print')

        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_print_sensitive(self, *args, **kwargs):
        """
        Command line auditing - printing
        :param lines:
        :param sensitive:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('print')
        log['sensitive'] = True

        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_input_prompt(self, question=None, sensitive=False, *args, **kwargs):
        """
        Command line auditing - printing
        :param question:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('input_prompt')
        if question is not None:
            log['question'] = self._valueize(question)

        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_input_enter(self, question=None, answer=None, sensitive=False, *args, **kwargs):
        """
        Command line auditing - printing
        :param question:
        :param answer:
        :param sensitive:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('input_prompt')
        if question is not None:
            log['question'] = self._valueize(question)
        if answer is not None:
            log['answer'] = self._valueize(answer)
        if sensitive:
            log['sensitive'] = self._valueize(sensitive)

        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_value(self, key=None, value=None, sensitive=False, *args, **kwargs):
        """
        Command line auditing - printing
        :param question:
        :param answer:
        :param sensitive:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('value')
        if key is not None:
            log['key'] = self._valueize(key)
        if value is not None:
            log['value'] = self._valueize(value)
        if sensitive:
            log['sensitive'] = self._valueize(sensitive)

        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_evt(self, evt, *args, **kwargs):
        """
        General audit logging
        :param evt:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog(evt)
        self._args_to_log(log, *args)
        self._kwargs_to_log(log, **kwargs)
        self._log(log)



