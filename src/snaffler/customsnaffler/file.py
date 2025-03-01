import copy
from pathlib import Path
from src.snaffler.customsnaffler.constants import EnumerationScope, MatchAction, MatchLoc, MatchListType, Triage
from typing import List
from src.snaffler.customsnaffler.rule import SnaffleRule

class SnafflerFileRule(SnaffleRule):
	def __init__(self, enumerationScope:EnumerationScope, id:str, ruleName:str, matchAction:MatchAction, category:list[str], relayTargets:List[str], description:str, matchLocation:MatchLoc, wordListType:MatchListType, matchLength:int, wordList:List[str], triage:Triage):
		super().__init__(enumerationScope, id, ruleName, matchAction, category, relayTargets, description, matchLocation, wordListType, matchLength, wordList, triage)
	
	def match(self, file):
		results = []
		if self.matchLocation == MatchLoc.FileName:
			print("A")
			for rex in self.wordList:
				s = rex.search(file)
				if s: results.append(s.group(0))

		elif self.matchLocation == MatchLoc.FileExtension:
			print("B")
			ext = Path(file).suffix
			if ext == '':
				return results
			for rex in self.wordList:
				s = rex.search(file)
				if s: results.append(s.group(0))
		elif self.matchLocation == MatchLoc.FilePath:
			print("C")
			for rex in self.wordList:
				s = rex.search(file)
				if s: results.append(s.group(0))
		else:
			print("H")
		"""
		elif self.matchLocation == MatchLoc.FileLength:
			return False
			if file.size == self.matchLength:
				return True
		"""
		return results

	def determine_action(self, file):
		return self.action, self.match(file)