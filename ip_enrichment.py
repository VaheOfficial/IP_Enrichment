#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from cortexutils.analyzer import Analyzer
from description import RECORDS
import json


class IPEnrichment(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.answer = None

    def process(self, query):

        record = RECORDS.get(query['name'])
        if record is not None:
            self.answer = {
                "Answer":[ 
                {
                    "name": query['name'],
                    "data": record
                }
                ]
            }
        else:
            self.answer = {
                "status": "error",
                "message": f"No record found for {query['name']}"
            }
    
    def run(self):
        if self.data_type not in ["ip"]:
            self.error("Wrong data type")

        target = self.getData()

        query = {
            "name" : target,
            "type" : "ANY"
        }
        target = ".".join(target.split('.')[::-1]) if self.data_type == "ip" else None

        self.process(query)
        if self.answer is not None:
           self.report(self.answer) 
           self.summary(self.answer)
        else:
            self.error("Something went wrong")
    
    def summary(self,raw):
        count = self.build_taxonomy("info", "IPEnrich 65 CYS ", "RecordsCount ", len(self.answer.get("data", [])))
        return {"taxonomies": [count]}


if __name__ == '__main__':
    IPEnrichment().run()
