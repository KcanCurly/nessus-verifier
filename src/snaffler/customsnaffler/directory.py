from src.snaffler.customsnaffler.constants import EnumerationScope, MatchAction, MatchLoc, MatchListType, Triage
from src.snaffler.customsnaffler.rule import SnaffleRule
from typing import List

class SnafflerDirectoryRule(SnaffleRule):
	def __init__(self, enumerationScope:EnumerationScope, id:str, ruleName:str, matchAction:MatchAction, category:list[str], relayTargets:List[str], description:str, matchLocation:MatchLoc, wordListType:MatchListType, matchLength:int, wordList:List[str], triage:Triage):
		super().__init__(enumerationScope, id, ruleName, matchAction, category, relayTargets, description, matchLocation, wordListType, matchLength, wordList, triage)
	
	def match(self, data):
		for rex in self.wordList:
			if rex.search(data) is not None:
				return True
		return False

	def determine_action(self, data):
		if self.match(data) is False:
			return None, None
		return self.action, self.triage