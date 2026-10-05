import sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
sys.path.insert(0,str(ROOT/'data'))
from services import validate_indicator, calculate_threat_risk, enrich_indicator
from generate_threat_data import generate
import app as service

class IndicatorTests(unittest.TestCase):
    def test_supported_shapes_and_syntax_only(self):
        expected={'192.0.2.1':'IP ADDRESS','example.com':'DOMAIN','https://sample.example.invalid/a':'URL','a'*64:'FILE HASH','CVE-2024-1234':'CVE ID'}
        for value, kind in expected.items():
            with self.subTest(value=value):
                result=validate_indicator(value); self.assertTrue(result['valid']); self.assertEqual(result['indicator_type'],kind)
    def test_bad_indicator(self): self.assertFalse(validate_indicator('not an indicator')['valid'])
    def test_risk_is_bounded(self): self.assertGreaterEqual(calculate_threat_risk('CRITICAL',100),0); self.assertLessEqual(calculate_threat_risk('CRITICAL',100),100)

class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        generate(2000); service.db_init(); service.app.testing=True; cls.client=service.app.test_client()
    def test_dataset_size(self): self.assertEqual(self.client.get('/api/dashboard/stats').json['observations'],2000)
    def test_local_search_and_no_match(self):
        result=self.client.get('/api/indicators/search?q=192.0.2.1').json
        self.assertTrue(result['validation']['valid']); self.assertIn('known_in_demo_dataset',result)
        absent=self.client.get('/api/indicators/search?q=203.0.113.254').json
        self.assertFalse(absent['known_in_demo_dataset'])
    def test_quiz_requires_all_answers(self): self.assertEqual(self.client.post('/api/quiz/submit',json={'answers':[1]}).status_code,400)

if __name__=='__main__': unittest.main()
