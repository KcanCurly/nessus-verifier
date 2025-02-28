
from typing import List, Dict, Tuple
import toml
import re
from src.snaffler.customsnaffler.constants import EnumerationScope, MatchAction, MatchLoc, MatchListType, Triage

class SnaffleRule:
	def __init__(self, scope, id, name, action, category, relay, description, matchLocation, wordListType, matchLength, wordList, triage) -> None:
		self.scope:EnumerationScope = scope
		self.id:str = id
		self.name:str = name
		self.action:MatchAction = action
		self.category:list[str] = category
		self.relay:list[str] = relay
		self.description:str = description
		self.matchLocation:MatchLoc = matchLocation
		self.wordListType:MatchListType = wordListType
		self.matchLength:int = matchLength
		self.wordList:List[re.Pattern] = wordList
		self.triage:Triage = triage
		self.__convert_wordlist()

	def __convert_wordlist(self):
		#convert wordlist to regex
		res = []
		for word in self.wordList:
			if self.wordListType == MatchListType.Regex:
				a=1
			elif self.wordListType == MatchListType.EndsWith:
				word = word + '$'
			elif self.wordListType == MatchListType.StartsWith:
				word = '^' + word
			elif self.wordListType == MatchListType.Contains:
				word = '.*' + word + '.*'
			elif self.wordListType == MatchListType.Exact:
				word = '^' + word + '$'
			res.append(re.compile(word, flags=re.IGNORECASE))
		self.wordList = res

	
	def match(self, data):
		for rex in self.wordList:
			if rex.search(data) is not None:
				return True
		return False

	def determine_action(self, data):
		if self.match(data) is False:
			return None, None
		return self.matchAction, self.triage
	
	def __repr__(self):
		return str(toml.dumps(self.to_dict()))
	
	@staticmethod
	def from_dict(datadict:Dict):
		from src.snaffler.customsnaffler.file import SnafflerFileRule
		from src.snaffler.customsnaffler.directory import SnafflerDirectoryRule
		from src.snaffler.customsnaffler.contents import SnafflerContentsEnumerationRule
		
		results = []
		if 'Rule' not in datadict:
			return []
		for d in datadict['Rule']:
			enumerationScope = EnumerationScope(d['scope'])
			ruleName = d.get('name', 'Unnamed Rule')
			matchAction = MatchAction(d['action'])
			relayTargets = d.get('RelayTargets', []) 
			description = d.get('Description', 'No description')
			matchLocation = MatchLoc(d['MatchLocation'])
			wordListType = MatchListType(d['WordListType'])
			matchLength = d.get('MatchLength', 0)
			wordList = d.get('WordList', [])
			triage = Triage(d.get('Triage', 'Gray'))
			if enumerationScope == EnumerationScope.File:
				obj = SnafflerFileRule
			elif enumerationScope == EnumerationScope.Directory:
				obj = SnafflerDirectoryRule
			elif enumerationScope == EnumerationScope.Content:
				obj = SnafflerContentsEnumerationRule
			else:
				raise NotImplementedError(f'EnumerationScope {enumerationScope} not implemented.')

			results.append(obj(enumerationScope, ruleName, matchAction, relayTargets, description, matchLocation, wordListType, matchLength, wordList, triage))
		return results

