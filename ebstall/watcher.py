#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import logging
import threading
import time


__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class Watcher(object):
    """
    Watcher object handles scenario with executing some piece of code after some timeout    
    """
    def __init__(self, fnc, timeout):
        self.fnc = fnc
        self.timeout = timeout
        self._thread = None
        self._paused = True
        self._lock = threading.Lock()
        self._stop_evt = threading.Event()
        self._last_evt = 0
        self.timedout = False

    def start(self, paused=False):
        """
        Starts the watcher
        :return: 
        """
        self._thread = threading.Thread(target=self._main)
        self._paused = paused
        self._thread.start()

    def signal(self):
        """
        Signalize event happened - postpone timeouting
        :return: 
        """
        self._paused = False
        with self._lock:
            self._last_evt = time.time()

    def stop(self):
        """
        Stops the watcher
        :return: 
        """
        self._paused = True
        self._stop_evt.set()

    def _main(self):
        """
        Thread main 
        :return: 
        """
        while not self._stop_evt.isSet():
            time.sleep(0.05)

            if self._paused:
                continue

            with self._lock:
                cur_time = time.time()
                if self._last_evt + self.timeout >= cur_time:
                    continue

            self.timedout = True
            self.fnc()
            return

