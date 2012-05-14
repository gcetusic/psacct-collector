#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
logging.basicConfig(level=logging.INFO)

import os
import re
import signal
import sys
import time
import urllib2

from threading import Thread

flags = {
    'is_running': True
}

changed_docs = {}

class ViewUpdater(object):
    """Updates the views.
    """
    
    # The smallest amount of changed documents before the views are updated
    MIN_NUM_OF_CHANGED_DOCS = 50
    
    # Set the minimum pause between calls to the database
    PAUSE = 5 # seconds
    
    # URL to the DB on the CouchDB server
    URL = "http://localhost:5984"
    
    # One entry for each design document 
    # in each database
    VIEWS = {
        'sysacct_records': {
            'commands': [
                'exectimes',
            ],
	    'machines': [
		'useractivity',
	    ],
	    'users': [
	        'commands',
	    ],
        }
    }
    
    def start(self):
        Thread(target=self._run).start()
    
    
    def _run(self):
        """Loop, checking for enough ``changed_docs`` to trigger a
          request to couchdb to re-index.
        """
        
        while flags['is_running']:
            try:
                for db_name, number_of_docs in changed_docs.items():
                    if number_of_docs >= self.MIN_NUM_OF_CHANGED_DOCS:
                        # Reset the value
                        del changed_docs[db_name]
                        # If there are views in the database, get them
                        if db_name in self.VIEWS:
                            logging.info('regenerating %s' % db_name)
                            db_views = self.VIEWS[db_name]
                            for design, views in db_views.iteritems():
                                for view in views:
                                    url = '%s/%s/_design/%s/_view/%s?limit=0' % (
                                        self.URL, db_name, design, view
                                    )
                                    urllib2.urlopen(url)
                time.sleep(self.PAUSE)
            except:
                flags['is_running'] = False
                raise
            
class NotificationConsumer(object):
    """Receives the update notification from CouchDB.
    """
    
    DB_NAME_EXPRESSION = re.compile(r'\"db\":\"(\w+)\"')
    
    def _run(self):
        """Consume update notifications from stdin.
        """
        
        while flags['is_running']:
            try:
                data = sys.stdin.readline()
            except:
                continue
            else:
                if not data: # exit
                    flags['is_running'] = False
                    break
                result = self.DB_NAME_EXPRESSION.search(data)
                if result:
                    db_name = result.group(1)
                    # Set to 0 if it hasn't been initialized before
                    if db_name not in changed_docs:
                        changed_docs[db_name] = 0
                    # Add one pending changed document to the list
                    # of documents in the DB
                    changed_docs[db_name] += 1
                
    def start(self):
        t = Thread(target=self._run)
        t.start()
        return t
        
def main():
    logging.info('update_notification handler (re)starting')
    consumer = NotificationConsumer()
    updater = ViewUpdater()
    updater.start()
    t = consumer.start()
    try:
        while flags['is_running']:
            t.join(10)
    except KeyboardInterrupt, err:
        flags['is_running'] = False
        
if __name__ == '__main__':
    main()
