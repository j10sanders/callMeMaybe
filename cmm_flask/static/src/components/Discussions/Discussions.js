import React from 'react';
import {GridList, GridTile} from 'material-ui/GridList';
import IconButton from 'material-ui/IconButton';
import Subheader from 'material-ui/Subheader';
import StarBorder from 'material-ui/svg-icons/toggle/star-border';
import axios from 'axios';

const styles = {
  root: {
    display: 'flex',
    flexWrap: 'wrap',
    justifyContent: 'space-around',
  },
  gridList: {
    width: 500,
    height: 450,
    overflowY: 'hidden',
  },
};

class Discussions extends React.Component {
	constructor(props) {
    super(props);
    this.state = {dps: [{
        image: 'images/grid-list/hats-829509_640.jpg',
        host: 'Hats',
        description: 'Hans',
        id:0,
      },]
    };
  }

  componentDidMount(){
  	axios.get(`${process.env.REACT_APP_USERS_SERVICE_URL}/api/discussions`)
  	  .then((response) => 
  	    this.setState({dps: response.data}))
  	  .catch(function (error) {
  	    console.log(error)
  	  })
    };



/**
 * A simple example of a scrollable `GridList` containing a [Subheader](/#/components/subheader).
 */
 render() {
//  	const tilesData = [
//   {
//     img: 'images/grid-list/00-52-29-429_640.jpg',
//     title: 'Breakfast',
//     author: 'jill111',
//   },
//   {
//     img: 'images/grid-list/burger-827309_640.jpg',
//     title: 'Tasty burger',
//     author: 'pashminu',
//   },
//   {
//     img: 'images/grid-list/camera-813814_640.jpg',
//     title: 'Camera',
//     author: 'Danson67',
//   },
//   {
//     img: 'images/grid-list/morning-819362_640.jpg',
//     title: 'Morning',
//     author: 'fancycrave1',
//   },
//   {
//     img: 'images/grid-list/hats-829509_640.jpg',
//     title: 'Hats',
//     author: 'Hans',
//   },
//   {
//     img: 'images/grid-list/honey-823614_640.jpg',
//     title: 'Honey',
//     author: 'fancycravel',
//   },
//   {
//     img: 'images/grid-list/vegetables-790022_640.jpg',
//     title: 'Vegetables',
//     author: 'jill111',
//   },
//   {
//     img: 'images/grid-list/water-plant-821293_640.jpg',
//     title: 'Water plant',
//     author: 'BkrmadtyaKarki',
//   },
// ];
    return (
	  <div style={styles.root}>
	    <GridList
	      cellHeight={180}
        id="GridlistID"
	      style={styles.gridList}
	    >
	      <Subheader>Discussion Profiles</Subheader>
	      {this.state.dps.map((dp) => (
	        <GridTile
	          key={dp.id}
	          title={dp.description}
	          subtitle={<span>by <b>{dp.host}</b></span>}
	          actionIcon={<IconButton><StarBorder color="white" /></IconButton>}
	        >
	          <img src={dp.image} />
	        </GridTile>
	      ))}
	    </GridList>
	  </div>
);
}
}

export default Discussions;