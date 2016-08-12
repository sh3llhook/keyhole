#!/usr/bin/env python

# tutorial: http://pythoncentral.io/introductory-tutorial-python-sqlalchemy/
# This script handles creating the db if it doesn't exist, adding a new table for a 
# new user.

# DB scheme:
# Each user has their own table in the database.
# id, IP, username, SSH key, password, comments

# id, uid, ip, uname, key, passw, comment

import sqlite3
import sys
import os
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()

class sean(Base):
    __tablename__ = 'sean'
    id = Column(Integer, primary_key=True)
    uid = Column(String(250), nullable=False)
    ip = Column(String(250), nullable=False)
    uname = Column(String(250), nullable=False)
    key = Column(String(250), nullable=False)
    passw = Column(String(250), nullable=True)
    comments = Column(String(250), nullable=True)

engine = create_engine('sqlite:///user_db.db')
Base.metadata.create_all(engine)
