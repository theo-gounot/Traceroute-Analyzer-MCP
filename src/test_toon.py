import pandas as pd
import unittest
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

from utils import to_toon

class TestToToon(unittest.TestCase):
    def test_basic_dataframe(self):
        df = pd.DataFrame({
            'col1': ['a', 'b'],
            'col2': [1, 2]
        })
        result = to_toon(df)
        lines = result.strip().split('\n')
        self.assertEqual(lines[0].strip(), "col1|col2")
        self.assertTrue("a|1" in result or "a|1.0" in result) # Integer might be converted to float if mixed? No, here distinct.
        self.assertTrue("b|2" in result or "b|2.0" in result)

    def test_float_formatting(self):
        df = pd.DataFrame({'val': [1.2345678, 0.000123456]})
        result = to_toon(df)
        # Check for 1.235 (rounding)
        self.assertIn("1.235", result)
        # Check for 0.0001235
        self.assertIn("0.0001235", result)

    def test_nan_handling(self):
        # Multi-column test
        df = pd.DataFrame({
            'a': [1, None],
            'b': [None, 2]
        })
        result = to_toon(df)
        lines = result.split('\n')
        self.assertEqual(lines[0].strip(), "a|b")
        # Row 1: 1| (since b is None) -> "1|" or "1|"" ?
        # Row 2: |2 (since a is None)
        
        # With default quoting, it should be "1|" and "|2" (no quotes for empty fields in CSV usually)
        self.assertIn("1|", lines[1]) 
        self.assertIn("|2", lines[2])
        self.assertNotIn('""', result) # Ensure no quotes for empty fields in multi-column context


    def test_empty_dataframe_with_columns(self):
        df = pd.DataFrame(columns=['col1', 'col2'])
        result = to_toon(df)
        self.assertEqual(result.strip(), "col1|col2")

if __name__ == '__main__':
    unittest.main()
