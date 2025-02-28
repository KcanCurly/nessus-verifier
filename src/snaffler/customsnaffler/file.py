import copy
from pathlib import Path
from src.snaffler.pysnaffler.rules.constants import EnumerationScope, MatchAction, MatchLoc, MatchListType, Triage
from typing import List
from src.snaffler.pysnaffler.rules.rule import SnaffleRule

class SnafflerFileRule(SnaffleRule):
	def __init__(self, enumerationScope:EnumerationScope, id:str, ruleName:str, matchAction:MatchAction, category:list[str], relayTargets:List[str], description:str, matchLocation:MatchLoc, wordListType:MatchListType, matchLength:int, wordList:List[str], triage:Triage):
		super().__init__(enumerationScope, id, ruleName, matchAction, category, relayTargets, description, matchLocation, wordListType, matchLength, wordList, triage)
	
	def match(self, smbfile):
		if self.matchLocation == MatchLoc.FileName:
			for rex in self.wordList:
				if rex.search(smbfile) is not None:
					return True
		elif self.matchLocation == MatchLoc.FileExtension:
			ext = Path(smbfile).suffix
			if ext == '':
				return False
			for rex in self.wordList:
				if rex.search(ext) is not None:
					return True
		elif self.matchLocation == MatchLoc.FilePath:
			for rex in self.wordList:
				if rex.search(smbfile) is not None:
					return True
		elif self.matchLocation == MatchLoc.FileLength:
			return False
			if smbfile.size == self.matchLength:
				return True
		return False

	def determine_action(self, smbfile):
		if self.match(smbfile) is False:
			return None, None
		return self.matchAction, self.triage