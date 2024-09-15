import Provider from './provider';
import Router from './router';
import Pages from './pages';

function App() {
  return (
    <>
      <Provider>
        <Router>
          <Pages />
        </Router>
      </Provider>
    </>
  );
}

export default App;
