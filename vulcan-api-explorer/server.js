'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

const sessionRoutes = require('./src/routes/session');
const sitesRoutes = require('./src/routes/sites');
const catalogRoutes = require('./src/routes/catalog');
const callRoutes = require('./src/routes/call');
const queryRoutes = require('./src/routes/query');

const PORT = Number(process.env.PORT) || 3100;

const app = express();
app.use(express.json({ limit: '15mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/auth', sessionRoutes);
app.use('/api/sites', sitesRoutes);
app.use('/api/catalog', catalogRoutes);
app.use('/api/call', callRoutes);
app.use('/api/query', queryRoutes);

app.listen(PORT, () => {
  console.log(`Vulcan API Explorer running at http://localhost:${PORT}`);
});
