from src.snaffler.customsnaffler.constants import EnumerationScope, MatchAction, MatchLoc, MatchListType, Triage
from typing import Dict, List, Tuple
from src.snaffler.customsnaffler.rule import SnaffleRule
from pathlib import PureWindowsPath
from glob import glob
import hashlib
from pathlib import Path
import tomllib

class SnafflerRuleSet:
    def __init__(self):
        self.fileEnumerationRules:Dict[str, SnaffleRule] = {}
        self.directoryEnumerationRules:Dict[str, SnaffleRule] = {}
        self.contentsEnumerationRules:Dict[str, SnaffleRule] = {}
        self.allRules:Dict[str, SnaffleRule] = {}
        self.unrollCache:Dict[str, List[SnaffleRule]] = {}

    def enum_directory(self, directory) -> Tuple[bool, List[Triage]]:
        rules = []
        for rule in self.directoryEnumerationRules.values():
            action, triage = rule.determine_action(directory)
            if action is MatchAction.Discard:
                return False, None
            if action is not None:
                rules.append(rule)
        
        return True, rules

    def enum_file(self, filename) -> Tuple[bool, List[SnaffleRule]]:
        """Returns True if the file should be enumerated, False if it should be discarded.
        Returns a list of rules that matched the file."""
        rules = []
        for rule in self.fileEnumerationRules.values():
            res, triage = rule.determine_action(filename)
            if res is None:
                continue
            if res == MatchAction.Discard:
                return False, [rule]
            else:
                rules.append(rule)
        
        return True, rules
                

    def load_rule(self, rule):
        """Adds a single rule to the ruleset"""
        self.allRules[rule.name] = rule
        if rule.scope == EnumerationScope.Directory:
            self.directoryEnumerationRules[rule.name] = rule
        elif rule.scope == EnumerationScope.File:
            self.fileEnumerationRules[rule.name] = rule
        elif rule.scope == EnumerationScope.Content:
            self.contentsEnumerationRules[rule.name] = rule

    def load_rules(self, rules:List[SnaffleRule]):
        """Adds all rules from a list of rules"""
        for rule in rules:
            self.load_rule(rule)
            print(rule)

    def load_rule_file(self, fpath):
        """Adds all rules from a single file"""
        with open(fpath, 'rb') as file:
            d = tomllib.load(file)
            a = SnaffleRule.from_dict(d)
            self.load_rules(a)

    def load_directory(self, directory):
        """Adds all rules from a directory recursively"""
        for rulefilepath in glob(directory + '/**/*.toml', recursive=True):
            self.load_rule_file(rulefilepath)

    def to_dict(self):
        return {
            'fileEnumerationRules' : self.fileEnumerationRules,
            'directoryEnumerationRules' : self.directoryEnumerationRules,
            'contentsEnumerationRules' : self.contentsEnumerationRules,
            'allRules' : self.allRules
        }

    @staticmethod
    def from_dict(d):
        ruleset = SnafflerRuleSet()
        ruleset.fileEnumerationRules = d['fileEnumerationRules']
        ruleset.directoryEnumerationRules = d['directoryEnumerationRules']
        ruleset.contentsEnumerationRules = d['contentsEnumerationRules']
        ruleset.allRules = d['allRules']
        return ruleset

    def pickle(self):
        """Pickle the ruleset"""
        import pickle
        import gzip
        import base64
        return base64.b64encode(gzip.compress(pickle.dumps(self.to_dict())))
	
    @staticmethod
    def unpickle(pickled):
        """Unpickle a ruleset"""
        import pickle
        import gzip
        import base64
        return SnafflerRuleSet.from_dict(pickle.loads(gzip.decompress(base64.b64decode(pickled))))

    @staticmethod
    def load_default_ruleset():
        script_dir = Path(__file__)
        target_dir = script_dir.parent / "rules"
        s = SnafflerRuleSet()
        s.load_directory(target_dir.__str__())
        return s

    @staticmethod
    def from_directory(dirpath):
        """Load all rules from a directory recirsively"""
        ruleset = SnafflerRuleSet()
        ruleset.load_directory(dirpath)
        return ruleset

    @staticmethod
    def from_file(filepath):
        """Load all rules from a single file"""
        ruleset = SnafflerRuleSet()
        ruleset.load_rule_file(filepath)
        return ruleset

    def unroll_relays(self, rules:List[SnaffleRule]) -> List[SnaffleRule]:
        lookupkey = ''
        for rule in rules:
            lookupkey += rule.name
        if lookupkey in self.unrollCache:
            return self.unrollCache[lookupkey]

        finalrules = {}
        for rule in rules:
            if rule.matchAction == MatchAction.Relay:
                # I can only hope there won't be nested relays
                # or worse: recursive relays...
                for relay in rule.relay:
                    if relay in self.allRules:
                        if relay not in finalrules:
                            finalrules[relay] = self.allRules[relay]
                        # keep it like this so we know which rule is already in the set
                        # and which one is missing
                    else:
                        print('Rule %s has relay target %s which is not a valid rule' % (rule.name, relay))
            else:
                finalrules[rule.name] = rule
        self.unrollCache[lookupkey] = finalrules.values()
        return finalrules.values()

    async def parse_file(self, filepath, rules:List[SnaffleRule], fsize:int = 0, chars_before_match:int = 0, chars_after_match:int = 0):
        finalrules = self.unroll_relays(rules)
        for rule in finalrules:
            if rule.scope == EnumerationScope.Content:
                res, err = rule.open_and_match(filepath, chars_before_match, chars_after_match)
                if err is not None:
                    yield None, rule, err
                if res:
                    yield res, rule, None