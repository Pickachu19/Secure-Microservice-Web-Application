import unittest
from app import app

class ProductServiceTestCase(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_product_list(self):
        response = self.app.get('/products')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Product', response.data)

if __name__ == '__main__':
    unittest.main()

