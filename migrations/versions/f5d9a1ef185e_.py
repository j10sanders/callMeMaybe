"""empty message

Revision ID: f5d9a1ef185e
Revises: 0c14c17b64b0
Create Date: 2018-04-05 14:40:30.344543

"""

# revision identifiers, used by Alembic.
revision = 'f5d9a1ef185e'
down_revision = '0c14c17b64b0'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('discussion_profiles', sa.Column('walletAddress', sa.String(), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('discussion_profiles', 'walletAddress')
    ### end Alembic commands ###
