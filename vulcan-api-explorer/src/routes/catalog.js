'use strict';

const express = require('express');
const { operationsCatalog } = require('../catalog');

const router = express.Router();

router.get('/', (req, res) => {
  res.json(operationsCatalog());
});

module.exports = router;
