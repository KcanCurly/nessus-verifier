from src.snaffler.customsnaffler.constants import EnumerationScope, MatchAction, MatchLoc, MatchListType, Triage
from src.snaffler.customsnaffler.rule import SnaffleRule
from typing import List

class SnafflerDirectoryRule(SnaffleRule):
	def __init__(self, enumerationScope:EnumerationScope, id:str, ruleName:str, matchAction:MatchAction, category:list[str], relayTargets:List[str], description:str, matchLocation:MatchLoc, wordListType:MatchListType, matchLength:int, wordList:List[str], triage:Triage, importance:str, dontignorecase:bool):
		super().__init__(enumerationScope, id, ruleName, matchAction, category, relayTargets, description, matchLocation, wordListType, matchLength, wordList, triage, importance, dontignorecase)
	
	def match(self, data):
		for rex in self.wordList:
			if rex.search(data):
				return True
		return False

	def determine_action(self, data):
		if not self.match(data):
			return None, None
		return self.action, self.triage