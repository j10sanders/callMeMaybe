import React from 'react';
import {GridList, GridTile} from 'material-ui/GridList';
import IconButton from 'material-ui/IconButton';
import Subheader from 'material-ui/Subheader';
import StarBorder from 'material-ui/svg-icons/toggle/star-border';


const styles = {
  root: {
    display: 'flex',
    flexWrap: 'wrap',
    justifyContent: 'space-around',
  },
  gridList: {
    width: 500,
    height: 450,
    overflowY: 'auto',
  },
};

class Clock extends React.Component {
	constructor(props) {
    super(props);
    // this.state = {date: new Date()};
  }

  componentDidMount(){
  	let discussions = 
  	axios.get(`${process.env.REACT_APP_USERS_SERVICE_URL}/api/discussions`)
  	  .then(function (response) {
  	    console.log(response)
  	  })
  	  .catch(function (error) {
  	    console.log(error);
  	  });
  }

const tilesData = [
  {
    img: 'images/grid-list/00-52-29-429_640.jpg',
    title: 'Breakfast',
    author: 'jill111',
  },
  {
    img: 'images/grid-list/burger-827309_640.jpg',
    title: 'Tasty burger',
    author: 'pashminu',
  },
  {
    img: 'images/grid-list/camera-813814_640.jpg',
    title: 'Camera',
    author: 'Danson67',
  },
  {
    img: 'images/grid-list/morning-819362_640.jpg',
    title: 'Morning',
    author: 'fancycrave1',
  },
  {
    img: 'images/grid-list/hats-829509_640.jpg',
    title: 'Hats',
    author: 'Hans',
  },
  {
    img: 'images/grid-list/honey-823614_640.jpg',
    title: 'Honey',
    author: 'fancycravel',
  },
  {
    img: 'images/grid-list/vegetables-790022_640.jpg',
    title: 'Vegetables',
    author: 'jill111',
  },
  {
    img: 'images/grid-list/water-plant-821293_640.jpg',
    title: 'Water plant',
    author: 'BkrmadtyaKarki',
  },
];

/**
 * A simple example of a scrollable `GridList` containing a [Subheader](/#/components/subheader).
 */
 render() {
    return (
	  <div style={styles.root}>
	    <GridList
	      cellHeight={180}
	      style={styles.gridList}
	    >
	      <Subheader>December</Subheader>
	      {tilesData.map((tile) => (
	        <GridTile
	          key={tile.img}
	          title={tile.title}
	          subtitle={<span>by <b>{tile.author}</b></span>}
	          actionIcon={<IconButton><StarBorder color="white" /></IconButton>}
	        >
	          <img src={tile.img} />
	        </GridTile>
	      ))}
	    </GridList>
	  </div>
);
}
}

export default GridListExampleSimple;