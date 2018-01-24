#!/usr/bin/python3
# -*- coding: utf-8 -*-

from pymongo import MongoClient

client = MongoClient()
db = client['test']
collection  = db['test']
post = {'name':'John', 'age': 24}
posts = db.posts
post_id = posts.insert_one(post).inserted_id
