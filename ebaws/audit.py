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
            else:
                self.audit_file = os.path.join(os.getcwd(), 'eb-audit.json')

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
            log[str(key)] = '%s' % value

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
        log['cmd'] = cmd
        if cwd is not None:
            log['cwd'] = cwd
        if retcode is not None:
            log['retcode'] = retcode
        if stdout is not None:
            log['stdout'] = stdout
        if stderr is not None:
            log['stderr'] = stderr
        if exception is not None:
            log['exception'] = '%s' % exception
        if exctrace is not None:
            log['exctrace'] = '%s' % exctrace

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
        log['src'] = src
        log['dst'] = dst

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
        log['src'] = src
        log['dst'] = dst

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
            log['chmod'] = data
        if data is not None:
            log['data'] = data

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
        log['name'] = fname

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
        log['name'] = fname
        if data is not None:
            log['data'] = data

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
        log['name'] = fname
        if chmod is not None:
            log['chmod'] = data
        if data is not None:
            log['data'] = data

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_download(self, url, *args, **kwargs):
        """
        Download action
        :param url:
        :return:
        """
        log = self._newlog('download')
        log['url'] = url

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
            log['url'] = url
        if desc is not None:
            log['desc'] = desc
        if data is not None:
            log['data'] = data

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
        log = self._newlog('request')
        if exception is not None:
            log['exception'] = '%s' % exception
        if exctrace is not None:
            log['exctrace'] = '%s' % exctrace
        else:
            try:
                log['exctrace'] = '%s' % traceback.format_exc()
            except:
                pass

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
        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_print(self, lines=None, *args, **kwargs):
        """
        Command line auditing - printing
        :param lines:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('print')
        if lines is not None:
            log['lines'] = lines

        self._kwargs_to_log(log, **kwargs)
        self._log(log)

    def audit_input_prompt(self, question=None, *args, **kwargs):
        """
        Command line auditing - printing
        :param question:
        :param args:
        :param kwargs:
        :return:
        """
        log = self._newlog('input_prompt')
        if question is not None:
            log['question'] = question

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
            log['question'] = question
        if answer is not None:
            log['answer'] = question

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
        self._kwargs_to_log(log, **kwargs)
        self._log(log)



