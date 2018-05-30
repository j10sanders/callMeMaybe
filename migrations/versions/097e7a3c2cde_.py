"""empty message

Revision ID: 097e7a3c2cde
Revises: e5aac0f0d101
Create Date: 2018-05-30 19:06:49.842557

"""

# revision identifiers, used by Alembic.
revision = '097e7a3c2cde'
down_revision = 'e5aac0f0d101'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('discussion_profiles', sa.Column('youtube', sa.String(), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('discussion_profiles', 'youtube')
    ### end Alembic commands ###